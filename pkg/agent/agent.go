package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/command"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/config"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/reconciliation"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/build"
	"github.com/fortnoxab/gitmachinecontroller/pkg/websocket"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// OnFunc is used in all the callbacks.
type OnFunc func(*protocol.WebsocketMessage) error

type Agent struct {
	Master     string
	oneShot    bool
	Dry        bool
	Hostname   string
	Zone       string
	wg         *sync.WaitGroup
	callbacks  map[string][]OnFunc
	client     websocket.Websocket
	mutex      sync.RWMutex
	config     *config.Config
	configFile string
	commander  command.Commander
}

func NewAgentFromContext(c *cli.Context) *Agent {
	m := &Agent{
		Master:     c.String("master"),
		configFile: c.String("config"),
		oneShot:    c.Bool("one-shot"),
		Dry:        c.Bool("dry"),
		Hostname:   c.String("hostname"),
		Zone:       c.String("zone"),
		wg:         &sync.WaitGroup{},
		callbacks:  make(map[string][]OnFunc),
		client:     websocket.NewWebsocketClient(),
		commander:  &command.Exec{},
	}
	return m
}
func NewAgent(configFile string, commander command.Commander, options ...func(*Agent)) *Agent {
	m := &Agent{
		wg:         &sync.WaitGroup{},
		callbacks:  make(map[string][]OnFunc),
		client:     websocket.NewWebsocketClient(),
		configFile: configFile,
		commander:  commander,
	}
	for _, o := range options {
		o(m)
	}
	return m
}

func WithTLSConfig(c *tls.Config) func(*Agent) {
	return func(s *Agent) {
		s.client.SetTLSConfig(c)
	}
}

func (a *Agent) Run(ctx context.Context) error {
	conf, err := config.FromFile(a.configFile)

	// we dont have a config file. Just save master from command line argument to configfile.
	if err != nil {
		if os.IsNotExist(err) {
			conf = &config.Config{
				Masters: config.Masters{&config.Master{URL: a.Master}},
			}
			err = os.MkdirAll(filepath.Dir(a.configFile), 0700)
			if err != nil {
				return err
			}

			err = config.ToFile(a.configFile, conf)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	a.config = conf

	return a.run(ctx)
}
func (a *Agent) run(pCtx context.Context) error {
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: time.RFC3339Nano, FullTimestamp: true})
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	if a.Hostname != "" {
		hostname = a.Hostname
	}

	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		for {
			master := a.config.FindMasterForConnection(pCtx, a.configFile, a.Zone)

			if pCtx.Err() != nil {
				return
			}
			ctx, cancel := context.WithCancel(pCtx)

			headers := http.Header{}
			headers.Add("X-HOSTNAME", hostname)
			headers.Add("X-VERSION", build.JSON())
			headers.Set("Authorization", a.config.Token)
			u, err := websocket.ToWS(master)
			if err != nil {
				logrus.Error(err)
				cancel()
				time.Sleep(1 * time.Second)
				continue
			}

			err = a.client.ConnectContext(ctx, u, headers)
			if err != nil {
				logrus.Error(err)
				cancel()

				if errors.Is(err, websocket.ErrUnauthorized) {
					// remove token in runtime if we get auth error. Then the machine will have to be accepted again.
					a.mutex.Lock()
					a.config.Token = ""
					a.mutex.Unlock()
				}
				time.Sleep(1 * time.Second)
				continue
			}

			select {
			case <-pCtx.Done():
				logrus.Info("stopping reconnect loop because:", pCtx.Err())
				cancel()
				return
			case err := <-a.client.Disconnected():
				logrus.Errorf("websocket: disconnected: %s", err)
				cancel()
				// connect again!
			}
		}
	}()

	ticker := time.NewTicker(time.Hour * 12)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		for {
			select {
			case <-ticker.C:
				msg, err := protocol.NewMessage("renew-agent-jwt", nil)
				if err != nil {
					logrus.Error(err)
					continue
				}
				err = a.WriteMessage(msg)
				if err != nil {
					logrus.Error(err)
				}

			case <-pCtx.Done():
				logrus.Debug("stopping jwt refresh loop")
				return
			}
		}
	}()

	a.On("machine-accepted", a.onMachineAccepted)
	a.On("machine-update", a.onMachineUpdate)
	a.On("run-command", a.onRunCommand)
	go a.reader(pCtx)
	a.wg.Wait()
	return nil
}

func (a *Agent) onMachineAccepted(msg *protocol.WebsocketMessage) error {
	var token string
	err := json.Unmarshal(msg.Body, &token)
	if err != nil {
		return err
	}

	a.mutex.Lock()
	a.config.Token = token
	a.mutex.Unlock()

	err = config.ToFile(a.configFile, a.config)
	if err != nil {
		return err
	}

	return a.client.Close() // force reconnect
}
func (a *Agent) onRunCommand(msg *protocol.WebsocketMessage) error {
	var cmd string
	err := json.Unmarshal(msg.Body, &cmd)
	if err != nil {
		return err
	}

	stdout, stderr, code, err := a.commander.RunWithCode(cmd)
	cr := &protocol.CommandResult{
		Stdout: stdout,
		Stderr: stderr,
		Online: true,
		Code:   code,
	}
	if err != nil {
		cr.Err = err.Error()
	}
	resp, err := protocol.NewCommandResult(msg.RequestID, cr)
	if err != nil {
		return err
	}

	err = a.WriteMessage(resp)
	if err != nil {
		return err
	}

	// return nil
	return err
}

func (a *Agent) onMachineUpdate(msg *protocol.WebsocketMessage) error {
	if msg.Source == protocol.GitSource && a.config.Ignore {
		logrus.Debug("ignore reconciliation since we have gmc.io/ignore=true")
		return nil
	}

	machine := &types.Machine{}
	err := json.Unmarshal(msg.Body, machine)
	if err != nil {
		return err
	}

	if machine.Metadata != nil &&
		machine.Metadata.Annotations != nil &&
		machine.Metadata.Annotations.Get("gmc.io/ignore") == "true" &&
		!a.config.Ignore {

		a.config.Ignore = true
		err = config.ToFile(a.configFile, a.config)
		if err != nil {
			return err
		}

		return a.doRecon(machine)
	} else {
		if msg.Source == protocol.ManualSource && a.config.Ignore {
			a.config.Ignore = false
			err := config.ToFile(a.configFile, a.config)
			if err != nil {
				return err
			}
		}
	}

	return a.doRecon(machine)
}

func (a *Agent) doRecon(machine *types.Machine) error {
	recon := reconciliation.NewMachineReconciler(a.commander, a.client)
	err := recon.Reconcile(machine)

	if a.oneShot {
		if err != nil {
			logrus.Error(err)
		}
		os.Exit(0) // Exit here after first sync if --one-shot is true
	}

	return err
}

func (a *Agent) reader(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Stopping websocket reader because:", ctx.Err())
			return
		case data := <-a.client.Read():
			msg, err := protocol.ParseMessage(data)
			if err != nil {
				logrus.Error("websocket reader:", err)
				continue
			}
			cbs := a.getCallbacks()
			for _, cb := range cbs[msg.Type] {
				err := cb(msg)
				if err != nil {
					logrus.Error(err)
					continue
				}
			}
			if cbs[msg.Type] == nil || len(cbs[msg.Type]) == 0 {
				logrus.WithFields(logrus.Fields{
					"type": msg.Type,
				}).Warn("got message but no one cared")
			}
		}
	}
}
func (a *Agent) getCallbacks() map[string][]OnFunc {
	cbs := make(map[string][]OnFunc)
	a.mutex.RLock()
	for k, v := range a.callbacks {
		cbs[k] = v
	}
	a.mutex.RUnlock()
	return cbs
}

// WaitForMessage is a helper method to wait for a specific message type.
func (a *Agent) WaitForMessage(msgType string, dst interface{}) error {
	for data := range a.client.Read() {
		msg, err := protocol.ParseMessage(data)
		if err != nil {
			return err
		}
		if msg.Type == msgType {
			return json.Unmarshal(msg.Body, dst)
		}
	}
	return nil
}

// WriteMessage writes a message to the server over websocket client.
func (a *Agent) WriteMessage(msg *protocol.WebsocketMessage) error {
	logrus.WithFields(logrus.Fields{
		"type": msg.Type,
		"body": string(msg.Body),
	}).Tracef("Send to server")
	return a.client.WriteJSON(msg)
}

// On sets up a callback that is run when a message received with type what.
func (a *Agent) On(what string, cb OnFunc) {
	a.mutex.Lock()
	a.callbacks[what] = append(a.callbacks[what], cb)
	a.mutex.Unlock()
}
