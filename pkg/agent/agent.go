package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/reconciliation"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/build"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// OnFunc is used in all the callbacks.
type OnFunc func(json.RawMessage) error

type Agent struct {
	Masters      []string
	OneShot      bool
	Dry          bool
	FakeHostname string
	// TODO save and fetch from config file
	JWTToken  string
	wg        *sync.WaitGroup
	callbacks map[string][]OnFunc
	client    Websocket
	mutex     sync.RWMutex
}

func NewAgentFromContext(c *cli.Context) *Agent {
	m := &Agent{
		Masters:      c.StringSlice("master"),
		OneShot:      c.Bool("one-shot"),
		Dry:          c.Bool("dry"),
		FakeHostname: c.String("fake-hostname"),
		wg:           &sync.WaitGroup{},
		callbacks:    make(map[string][]OnFunc),
		client:       New(),
	}
	return m
}

func (a *Agent) Run(ctx context.Context) error {
	return a.run(ctx)
}
func (a *Agent) run(pCtx context.Context) error {
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: time.RFC3339Nano, FullTimestamp: true})
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	if a.FakeHostname != "" {
		hostname = a.FakeHostname
	}

	headers := http.Header{}
	headers.Add("X-HOSTNAME", hostname)
	headers.Add("X-VERSION", build.JSON())

	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		for {
			master := a.findMasterForConnection(pCtx)

			if pCtx.Err() != nil {
				return
			}
			ctx, cancel := context.WithCancel(pCtx)

			a.mutex.RLock()
			headers.Set("Authorization", a.JWTToken)
			a.mutex.RUnlock()
			err = a.client.ConnectContext(ctx, master, headers)
			if err != nil {
				logrus.Error(err)
			}

			select {
			case <-pCtx.Done():
				logrus.Info("Stopping reconnect loop because:", pCtx.Err())
				cancel()
				return
			case <-a.client.Disconnected():
				cancel()
				// connect again!
			}
		}
	}()

	a.On("machine-accepted", a.onMachineAccepted)
	a.On("machine-update", a.onMachineUpdate)
	go a.reader(pCtx)
	a.wg.Wait()
	return nil
}

func (a *Agent) findMasterForConnection(ctx context.Context) string {
	for {
		for _, master := range a.Masters {
			err := a.isMasterAlive(master)
			if err != nil {
				continue
			}
			return master
		}
		if ctx.Err() != nil {
			return ""
		}

		logrus.Error("found no working master will sleep 10 seconds and try again")
		delay := time.NewTimer(time.Second * 10)
		select {
		case <-delay.C:
		case <-ctx.Done():
			if !delay.Stop() {
				<-delay.C
			}
			return ""
		}
	}
}
func (a *Agent) isMasterAlive(master string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u, err := wsToHost(master)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	data := &struct {
		Masters []string
	}{}

	err = json.NewDecoder(resp.Body).Decode(data)
	if err != nil {
		return err
	}

	// TODO save masters to local config
	fmt.Println("got hosts from up-v1")
	for _, m := range data.Masters {
		fmt.Println(hostToWs(m))
	}

	return nil
}

func wsToHost(master string) (string, error) {
	u, err := url.Parse(master)
	if err != nil {
		return "", err
	}

	if u.Scheme == "ws" {
		u.Scheme = "http"
	}
	if u.Scheme == "wss" {
		u.Scheme = "https"
	}
	u.Path = "/api/up-v1"
	return u.String(), nil
}

func hostToWs(master string) (string, error) {
	u, err := url.Parse(master)
	if err != nil {
		return "", err
	}

	if u.Scheme == "http" {
		u.Scheme = "ws"
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	}
	u.Path = "/api/websocket-v1"
	return u.String(), nil
}

func (a *Agent) onMachineAccepted(b json.RawMessage) error {
	var token string
	err := json.Unmarshal(b, &token)
	if err != nil {
		return err
	}

	a.mutex.Lock()
	// TODO we must save the token to config file on disk.
	a.JWTToken = token
	a.mutex.Unlock()
	return a.client.Close() // force reconnect
}

func (a *Agent) onMachineUpdate(b json.RawMessage) error {
	recon := &reconciliation.MachineReconciler{}

	machine := &types.Machine{}
	err := json.Unmarshal(b, machine)
	if err != nil {
		return err
	}

	return recon.Reconcile(machine)
	// return nil
}

func (a *Agent) reader(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			logrus.Info("Stopping websocket reader because:", ctx.Err())
			return
		case data := <-a.client.Read():
			msg, err := protocol.ParseMessage(data)
			if err != nil {
				logrus.Error("websocket reader:", err)
				continue
			}
			cbs := a.getCallbacks()
			for _, cb := range cbs[msg.Type] {
				err := cb(msg.Body)
				if err != nil {
					logrus.Error(err)
					continue
				}
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
		"body": msg.Body,
	}).Tracef("Send to server")
	return a.client.WriteJSON(msg)
}

// On sets up a callback that is run when a message received with type what.
func (a *Agent) On(what string, cb OnFunc) {
	a.mutex.Lock()
	a.callbacks[what] = append(a.callbacks[what], cb)
	a.mutex.Unlock()
}
