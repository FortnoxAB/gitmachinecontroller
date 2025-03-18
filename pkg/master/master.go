package master

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/git/gogit"
	"github.com/fluxcd/pkg/git/repository"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/config"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master/webserver"
	"github.com/fortnoxab/gitmachinecontroller/pkg/secrets"
	"github.com/olahol/melody"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
)

/*
TODO
	Think about HA?
HA
* clients connect to prefered master
* admin command knows all masters
	* do we want leaderelection so only one syncs from git? Probably!
	* how to ensure clients fetches from the current leader?

*/

type websocketRequestResponse struct {
	list  map[string]chan *websocketRequest
	mutex *sync.RWMutex
}

var requestResponseStore = &websocketRequestResponse{
	list:  make(map[string]chan *websocketRequest),
	mutex: &sync.RWMutex{},
}

func (r *websocketRequestResponse) Done(reqID string) {
	r.mutex.Lock()
	delete(r.list, reqID)
	r.mutex.Unlock()
}

func (r *websocketRequestResponse) WaitForResponse(reqID string) chan *websocketRequest {
	if ch := r.Ch(reqID); ch != nil {
		return ch
	}
	ch := make(chan *websocketRequest)
	r.mutex.Lock()
	r.list[reqID] = ch
	r.mutex.Unlock()
	return ch
}
func (r *websocketRequestResponse) Ch(reqID string) chan *websocketRequest {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.list[reqID]
}

type Master struct {
	GitURL            string
	GitBranch         string
	GitPath           string
	GitUser           string
	GitPollInterval   time.Duration
	GitIdentifyPath   string
	GitKnownHostsPath string
	GitPassPhrase     string
	SecretKey         string
	JWTKey            string
	WsPort            string
	Masters           config.Masters
	EnableMetrics     bool
	webserver         *webserver.Webserver
	machineStateCh    chan types.MachineStateQuestion
	secretHandler     *secrets.Handler
	RedisClient       redis.Cmdable
}

func NewMasterFromContext(c *cli.Context) *Master {

	m := &Master{
		GitURL:            c.String("git-url"),
		GitBranch:         c.String("git-branch"),
		GitPath:           c.String("git-path"),
		GitUser:           c.String("git-user"),
		GitPollInterval:   c.Duration("git-poll-interval"),
		GitIdentifyPath:   c.String("git-identity-path"),
		GitPassPhrase:     c.String("git-identity-passphrase"),
		GitKnownHostsPath: c.String("git-known-hosts-path"),
		SecretKey:         c.String("secret-key"),
		JWTKey:            c.String("jwt-key"),
		WsPort:            c.String("port"),
		EnableMetrics:     true,
	}
	if c.String("redis-url") != "" {
		opt, err := redis.ParseURL(c.String("redis-url"))
		if err != nil {
			logrus.Fatalf("error parsing redis url, err: %s", err)
			return nil
		}
		m.RedisClient = redis.NewClient(opt)
	}

	masters := config.Masters{}
	for _, m := range c.StringSlice("master") {
		u, err := url.Parse(m)
		if err != nil {
			logrus.Fatalf("error parsing master url, err: %s", err)
			return nil
		}

		z := u.Query().Get("zone")
		u.RawQuery = ""
		master := &config.Master{
			URL:  u.String(),
			Zone: z,
		}
		masters = append(masters, master)
	}
	m.Masters = masters

	return m
}

func (m *Master) Run(ctx context.Context) error {
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: time.RFC3339Nano, FullTimestamp: true})
	m.machineStateCh = make(chan types.MachineStateQuestion)
	m.secretHandler = secrets.NewHandler(m.SecretKey)
	m.webserver = webserver.New(m.WsPort, m.JWTKey, m.Masters, m.secretHandler)
	m.webserver.MachineStateCh = m.machineStateCh
	m.webserver.EnableMetrics = m.EnableMetrics
	go m.webserver.Start(ctx)

	return m.run(ctx)
}

type websocketRequest struct {
	Request *protocol.WebsocketMessage
	Sess    *melody.Session
}

type machineUpdate struct {
	Source  protocol.Source
	Machine *types.Machine
}

func (m *Master) run(ctx context.Context) error {
	u, err := url.Parse(m.GitURL)
	if err != nil {
		return err
	}

	authData, err := m.identity()
	if err != nil {
		return err
	}

	authOpts, err := git.NewAuthOptions(*u, authData)
	if err != nil {
		return err
	}
	cloneOpts := repository.CloneConfig{
		ShallowClone: true,
	}
	cloneOpts.Branch = m.GitBranch

	ticker := time.NewTicker(m.GitPollInterval)

	machineUpdateCh := make(chan machineUpdate)
	syncCh := make(chan *types.Machine)
	websocketCh := make(chan *websocketRequest)
	go m.stateRunner(ctx, syncCh, websocketCh, machineUpdateCh)
	go func() {
		for {
			select {
			case update := <-machineUpdateCh:
				syncCh <- update.Machine
				err = m.secretHandler.DecryptTasksFilesContent(update.Machine.Spec.Tasks)
				if err != nil {
					logrus.Error(err)
					continue
				}
				msg, err := protocol.NewMachineUpdate(update.Source, update.Machine)
				if err != nil {
					logrus.Error(err)
					continue
				}
				err = m.webserver.Websocket.BroadcastFilter(msg, func(s *melody.Session) bool {
					host, exists := s.Get("host")
					if exists && host.(string) != update.Machine.Metadata.Name {
						return false
					}
					if a, exists := s.Get("allowed"); exists && a.(bool) {
						logrus.Debugf("sending machine config to host %s from %s", host.(string), update.Source)
						return true
					}
					return false
				})
				if err != nil {
					logrus.Error(err)
					continue
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	m.webserver.Websocket.HandleMessage(func(sess *melody.Session, msg []byte) {
		pkt, err := protocol.ParseMessage(msg)
		if err != nil {
			logrus.Error(err)
			return
		}
		host, _ := sess.Get("host")
		pkt.From = host.(string)
		websocketCh <- &websocketRequest{
			Request: pkt,
			Sess:    sess,
		}
	})

	err = m.clone(ctx, authOpts, cloneOpts, machineUpdateCh)
	if err != nil {
		logrus.Error(err)
	}

	for {
		select {
		case <-ticker.C:
			err = m.clone(ctx, authOpts, cloneOpts, machineUpdateCh)
			if err != nil {
				// TODO error metrics for alarms?
				logrus.Error(err)
			}

		case <-ctx.Done():
			logrus.Debug("stopping cloneloop")
			return nil
		}
	}

	// if ref := obj.Spec.Reference; ref != nil {
	// https://github.com/fluxcd/source-controller/blob/16fed8995d1f5ba818697220fd2020f78e2cc630/controllers/gitrepository_controller.go#L733
	// cloneOpts.Branch = ref.Branch
	// cloneOpts.Commit = ref.Commit
	// cloneOpts.Tag = ref.Tag
	// cloneOpts.SemVer = ref.SemVer
	// }
}

func (m *Master) stateRunner(ctx context.Context, ch chan *types.Machine, websocketCh chan *websocketRequest, machineUpd chan machineUpdate) {
	machines := make(map[string]*types.MachineState)
	for {
		select {
		case request := <-websocketCh:
			err := m.handleRequest(ctx, machines, request, machineUpd)
			if err != nil {
				logrus.Error(err)
			}

		case req := <-m.machineStateCh:
			req.ReplyCh <- machines
		case machine := <-ch:
			machines[machine.Metadata.Name] = &types.MachineState{
				Metadata:   machine.Metadata,
				IP:         machine.Spec.IP,
				LastUpdate: time.Now(),
			}
		case <-ctx.Done():
			logrus.Debug("stopping stateRunner")
			return
		}
	}
}

func (m *Master) filterSessions(machines map[string]*types.MachineState, rex, sel string) ([]*melody.Session, []string, error) {
	rege, err := regexp.Compile(rex)
	if err != nil {
		return nil, nil, err
	}
	sessions, err := m.webserver.Websocket.Sessions()
	if err != nil {
		return nil, nil, err
	}
	sendTo := []*melody.Session{}

	filteredMachines := make(map[string]bool)
	for _, m := range machines {
		if rex == "" && sel == "" {
			filteredMachines[m.Metadata.Name] = false
			continue
		}
		// regexp filter
		if rex != "" && rege.MatchString(m.Metadata.Name) {
			filteredMachines[m.Metadata.Name] = false
		}

		// labelselector filter
		if sel != "" {
			selector, err := labels.Parse(sel)
			if err != nil {
				return nil, nil, err
			}
			if selector.Matches(m.Metadata.Labels) {
				filteredMachines[m.Metadata.Name] = false
			}
		}
	}

	for _, s := range sessions {
		if a, _ := s.Get("allowed"); !a.(bool) {
			continue
		}
		h, _ := s.Get("host")
		host := h.(string)
		if host == "" {
			continue // only send to agents which has host set and not admin sessions.
		}
		if _, ok := filteredMachines[host]; !ok {
			// we are not filtered
			continue
		}
		filteredMachines[host] = true // session is alive
		sendTo = append(sendTo, s)
	}
	offline := []string{}
	for host, online := range filteredMachines {
		if !online {
			offline = append(offline, host)
		}
	}

	return sendTo, offline, nil
}

func (m *Master) handleRequest(ctx context.Context, machines map[string]*types.MachineState, r *websocketRequest, machineUpdateCh chan machineUpdate) error {
	sess := r.Sess
	switch r.Request.Type {
	case "renew-agent-jwt":
		a, _ := sess.Get("allowed")
		host, _ := sess.Get("host")
		if !a.(bool) || host.(string) == "" {
			return fmt.Errorf("renew not allowed for %s", host.(string))
		}
		return m.webserver.ApproveAgent(host.(string))

	case "run-command-request":
		if admin, _ := sess.Get("admin"); !admin.(bool) {
			sendIsLast(sess, r.Request.RequestID)
			return fmt.Errorf("run-command-request permission denied")
		}
		cmdReq := &protocol.RunCommandRequest{}
		err := json.Unmarshal(r.Request.Body, cmdReq)
		if err != nil {
			return err
		}

		sendTo, offline, err := m.filterSessions(machines, cmdReq.Regexp, cmdReq.LabelSelector)
		if err != nil {
			return err
		}

		onlineLen := len(sendTo)
		logrus.Debugf("will send command request to cnt: %d", onlineLen)
		logrus.Debugf("offline machines: %#v", offline)

		if onlineLen+len(offline) == 0 {
			sendIsLast(sess, r.Request.RequestID)
			return fmt.Errorf("found zero hosts to send command to")
		}

		for _, host := range offline {
			b, err := protocol.NewCommandResult(r.Request.RequestID, &protocol.CommandResult{
				Online: false,
			})
			if err != nil {
				return err
			}
			b.From = host
			msg, err := b.Encode()
			if err != nil {
				return err
			}

			err = sess.Write(msg)
			if err != nil {
				return err
			}
		}

		go func() {
			defer requestResponseStore.Done(r.Request.RequestID)
			defer sendIsLast(sess, r.Request.RequestID)
			//TODO new ctx for timeout when agent does not respond.
			for range sendTo {
				select {
				case resp := <-requestResponseStore.WaitForResponse(r.Request.RequestID):
					d, err := json.Marshal(resp.Request)
					if err != nil {
						logrus.Error(err)
						return
					}

					err = sess.Write(d)
					if err != nil {
						logrus.Error(err)
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		logrus.Infof("we will run command: %s", cmdReq.Command)

		msg, err := protocol.NewMessage("run-command", cmdReq.Command)
		if err != nil {
			return err
		}

		msg.RequestID = r.Request.RequestID
		b, err := msg.Encode()
		if err != nil {
			return err
		}
		requestResponseStore.WaitForResponse(r.Request.RequestID)
		err = m.webserver.Websocket.BroadcastMultiple(b, sendTo)
		if err != nil {
			return err
		}

	case "command-result":
		ch := requestResponseStore.Ch(r.Request.RequestID)
		if ch == nil {
			return fmt.Errorf("no one is waiting for response")
		}
		ch <- r
	case "admin-apply-spec":
		if admin, _ := sess.Get("admin"); !admin.(bool) {
			return fmt.Errorf("admin-apply-spec permission denied")
		}
		defer sendIsLast(sess, r.Request.RequestID)
		machine := &types.Machine{}
		err := json.Unmarshal(r.Request.Body, machine)
		if err != nil {
			return err
		}
		logrus.Info("sending admin-apply-spec from master")
		machineUpdateCh <- machineUpdate{Machine: machine, Source: protocol.ManualSource}

	case "agent-aqure-lock":
		if admin, _ := sess.Get("allowed"); !admin.(bool) {
			return fmt.Errorf("agent-aqure-lock permission denied")
		}
		l := &protocol.AgentLock{}
		err := json.Unmarshal(r.Request.Body, l)
		if err != nil {
			return err
		}

		hasLock, err := aquireLock(ctx, m.RedisClient, l.Key, r.Request.From, time.Duration(l.TTL))
		if err != nil {
			return err
		}

		response := &protocol.WebsocketMessage{
			Type:      "agent-aqured-lock",
			RequestID: r.Request.RequestID,
		}
		if !hasLock {
			response.Type = "agent-failed-lock"
		}

		b, err := response.Encode()
		if err != nil {
			return err
		}

		err = sess.Write(b)
		if err != nil {
			return err
		}
	case "agent-release-lock":
		if admin, _ := sess.Get("allowed"); !admin.(bool) {
			return fmt.Errorf("agent-release-lock permission denied")
		}
		l := &protocol.AgentLock{}
		err := json.Unmarshal(r.Request.Body, l)
		if err != nil {
			return err
		}
		err = releaseLock(ctx, m.RedisClient, l.Key)
		if err != nil {
			return err
		}

		err = sess.Write([]byte(`{"hasLock":false}`))
		if err != nil {
			return err
		}
	}
	return nil
}

func releaseLock(ctx context.Context, redisClient redis.Cmdable, key string) error {
	_, err := redisClient.Del(ctx, "gmc.lock"+key).Result()
	if err == redis.Nil {
		return err
	}
	return err
}
func aquireLock(ctx context.Context, redisClient redis.Cmdable, key, id string, ttl time.Duration) (bool, error) {
	isLeader, err := redisClient.SetNX(ctx, "gmc.lock"+key, id, ttl).Result()

	if err == nil && isLeader {
		logrus.Debug("aquired new leader lock")
		return true, nil
	}

	lockId, err := redisClient.Get(ctx, "gmc.lock"+key).Result()
	if err != nil {
		return false, err
	}
	logrus.Debugf("current leader is: %s", lockId)
	return lockId == id, nil
}

func sendIsLast(sess *melody.Session, reqID string) {
	msg := &protocol.WebsocketMessage{
		Type:      "last_message",
		RequestID: reqID,
	}
	b, err := msg.Encode()
	if err != nil {
		logrus.Errorf("sendIsLast error: %s", err)
	}

	err = sess.Write(b)
	if err != nil {
		logrus.Errorf("sendIsLast error: %s", err)
	}
}

type Cloner interface {
	Clone(ctx context.Context, url string, cloneOpts repository.CloneConfig) (*git.Commit, error)
	Close()
}

type testCloner struct {
	dir string
}

func (tc *testCloner) Clone(ctx context.Context, URL string, cloneOpts repository.CloneConfig) (*git.Commit, error) {

	u, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	from := filepath.Join(cwd, u.Path)
	logrus.Infof("testCloner: copy %s to %s", from, tc.dir)
	err = os.CopyFS(tc.dir, os.DirFS(from))
	return nil, err
}
func (tc *testCloner) Close() {

}

func (m *Master) clone(ctx context.Context, authOpts *git.AuthOptions, cloneOpts repository.CloneConfig, manifestCh chan machineUpdate) error {
	dir, err := os.MkdirTemp("", "gmc")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	var gitClient Cloner
	if authOpts.Host == "test" {
		gitClient = &testCloner{dir: dir}
	} else {
		gitClient, err = gogit.NewClient(dir, authOpts)
		if err != nil {
			return err
		}
	}
	defer gitClient.Close()

	ctx1, cancel := context.WithTimeout(ctx, time.Minute*1) // TODO make this configurable?
	defer cancel()
	commit, err := gitClient.Clone(ctx1, m.GitURL, cloneOpts)
	if err != nil {
		return err
	}
	logrus.Debugf("cloned %s from %s", commit, m.GitURL)

	files, err := os.ReadDir(filepath.Join(dir, m.GitPath))
	if err != nil {
		return err
	}

	for _, file := range files {
		machine := &types.Machine{}
		path := filepath.Join(dir, m.GitPath, file.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			logrus.Errorf("error opening: %s err: %s", path, err)
			continue
		}

		if len(b) == 0 {
			continue // skip empty files
		}

		err = yaml.Unmarshal(b, machine)
		if err != nil {
			logrus.Errorf("error yaml parse: %s err: %s", path, err)
			continue
		}
		select {
		case manifestCh <- machineUpdate{Machine: machine, Source: protocol.GitSource}:
		case <-ctx.Done():
			logrus.Debug("stopping clone")
			return nil
		}
	}
	return nil
}

func (m *Master) identity() (map[string][]byte, error) {
	authData := make(map[string][]byte)

	i, err := os.ReadFile(m.GitIdentifyPath)
	if err != nil {
		logrus.Warnf("error fetching GitIdentifyPath: %s", err)
	}
	authData["identity"] = i

	kh, err := os.ReadFile(m.GitKnownHostsPath)
	if err != nil {
		logrus.Warnf("error fetching GitKnownHostsPath: %s", err)
	}
	authData["known_hosts"] = kh

	if m.GitPassPhrase != "" {
		authData["password"] = []byte(m.GitPassPhrase)
	}

	return authData, nil
}
