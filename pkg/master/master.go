package master

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/git/gogit"
	"github.com/fluxcd/pkg/git/repository"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master/webserver"
	"github.com/olahol/melody"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
)

/*
TODO
	Think about HA?
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
	Masters           []string
	webserver         *webserver.Webserver
	machineStateCh    chan types.MachineStateQuestion
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
		Masters:           c.StringSlice("master"),
	}
	return m
}

// testrun with
// gmc master --git-path "jsonnet/vms/manifests/main" --git-url "ssh://git@git.fnox.se:7999/fo/infra.git" --git-branch "feature/gitmachine" --git-identity-path /home/jonaz/.ssh/id_rsa --git-known-hosts-path /home/jonaz/.ssh/known_hosts --git-identity-passphrase asdfasdf

func (m *Master) Run(ctx context.Context) error {
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: time.RFC3339Nano, FullTimestamp: true})
	m.machineStateCh = make(chan types.MachineStateQuestion)
	m.webserver = webserver.New(m.WsPort, m.JWTKey, m.Masters)
	m.webserver.MachineStateCh = m.machineStateCh
	go m.webserver.Start(ctx)

	return m.run(ctx)
}

type websocketRequest struct {
	Request *protocol.WebsocketMessage
	Sess    *melody.Session
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
	cloneOpts := repository.CloneOptions{
		ShallowClone: true,
	}
	cloneOpts.Branch = m.GitBranch

	ticker := time.NewTicker(m.GitPollInterval)

	manifestCh := make(chan *types.Machine)
	syncCh := make(chan *types.Machine)
	websocketCh := make(chan *websocketRequest)
	go m.stateRunner(ctx, syncCh, websocketCh)
	go func() {
		/* TODO */
		for {
			select {
			case manifest := <-manifestCh:
				syncCh <- manifest
				// TODO template most string values to support secrets?
				msg, err := protocol.NewMachineUpdate(protocol.GitSource, manifest)
				if err != nil {
					logrus.Error(err)
					continue
				}
				err = m.webserver.Websocket.BroadcastFilter(msg, func(s *melody.Session) bool {
					host, exists := s.Get("host")
					if exists && host.(string) != manifest.Metadata.Name {
						return false
					}
					if a, exists := s.Get("allowed"); exists && a.(bool) {
						logrus.Debugf("sending machine config to host %s", host.(string))
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
		host, ok := sess.Get("host")
		if !ok {
			logrus.Error("did not find host field in the ws session")
			return
		}
		pkt.From = host.(string)
		websocketCh <- &websocketRequest{
			Request: pkt,
			Sess:    sess,
		}
	})

	err = m.clone(ctx, authOpts, cloneOpts, manifestCh)
	if err != nil {
		logrus.Error(err)
	}

	for {
		select {
		case <-ticker.C:
			err = m.clone(ctx, authOpts, cloneOpts, manifestCh)
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

func (m *Master) stateRunner(ctx context.Context, ch chan *types.Machine, websocketCh chan *websocketRequest) {
	//TODO add timestamp and IP and make it accessable from /pending-machines to print all machines?
	machines := make(map[string]*types.MachineState)
	for {
		select {
		case request := <-websocketCh:
			err := m.handleRequest(ctx, machines, request.Sess, request)
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

func (m *Master) handleRequest(ctx context.Context, machines map[string]*types.MachineState, sess *melody.Session, r *websocketRequest) error {
	switch r.Request.Type {
	case "run-command-request":
		cmdReq := &protocol.RunCommandRequest{}
		err := json.Unmarshal(r.Request.Body, cmdReq)
		if err != nil {
			return err
		}

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

		sendTo, offline, err := m.filterSessions(machines, cmdReq.Regexp, cmdReq.LabelSelector)
		if err != nil {
			return err
		}

		onlineLen := len(sendTo)
		max := onlineLen + len(offline)
		logrus.Debugf("will send command request to cnt: %d", max)
		logrus.Debugf("offline machines: %#v", offline)
		sendExpectedReadCount(sess, r.Request.RequestID, max)

		if max == 0 {
			return fmt.Errorf("found zero hosts to send command to")
		}

		for _, host := range offline {
			b, err := protocol.NewCommandResult(msg.RequestID, &protocol.CommandResult{
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
			i := -1
			for {
				i++
				if i >= onlineLen {
					logrus.Debug("got all the responses")
					return
				}
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
	}
	return nil
}

func sendExpectedReadCount(sess *melody.Session, reqID string, cnt int) error {
	resultCoutnMsg, err := protocol.NewMessage("expected-result-count", cnt)
	if err != nil {
		return err
	}
	resultCoutnMsg.RequestID = reqID
	resCnt, err := resultCoutnMsg.Encode()
	return sess.Write(resCnt)
}

func (m *Master) clone(ctx context.Context, authOpts *git.AuthOptions, cloneOpts repository.CloneOptions, manifestCh chan *types.Machine) error {
	dir, err := ioutil.TempDir("", "gmc")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	gitClient, err := gogit.NewClient(dir, authOpts)
	if err != nil {
		return err
	}
	defer gitClient.Close()

	// TODO context timeout here.
	commit, err := gitClient.Clone(ctx, m.GitURL, cloneOpts)
	if err != nil {
		return err
	}
	logrus.Debugf("cloned %s from %s", commit, m.GitURL)

	files, err := os.ReadDir(filepath.Join(dir, m.GitPath))

	for _, file := range files {
		machine := &types.Machine{}
		path := filepath.Join(dir, m.GitPath, file.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			logrus.Errorf("error opening: %s err: %s", path, err)
			continue
		}

		err = yaml.Unmarshal(b, machine)
		if err != nil {
			logrus.Errorf("error yaml parse: %s err: %s", path, err)
			continue
		}
		select {
		case manifestCh <- machine:
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
		return nil, err
	}
	authData["identity"] = i

	kh, err := os.ReadFile(m.GitKnownHostsPath)
	if err != nil {
		return nil, err
	}
	authData["known_hosts"] = kh

	if m.GitPassPhrase != "" {
		authData["password"] = []byte(m.GitPassPhrase)
	}

	return authData, nil
}

func (m *Master) encryptSecret(plaintext []byte) (string, error) {
	key := sha256.Sum256([]byte(m.SecretKey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return string(ciphertext), nil
}

func (m *Master) decryptSecret(ciphertext []byte) (string, error) {
	key := sha256.Sum256([]byte(m.SecretKey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
