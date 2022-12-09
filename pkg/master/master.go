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
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/git/gogit"
	"github.com/fluxcd/pkg/git/repository"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master/webserver"
	"github.com/olahol/melody"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

/*
TODO
	Think about HA?
	* do we want leaderelection so only one syncs from git? Probably!
	* how to ensure clients fetches from the current leader?

*/

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
	WsPort            string
	webserver         *webserver.Webserver
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
		WsPort:            c.String("port"),
	}
	return m
}

// testrun with
// gmc master --git-path "jsonnet/vms/manifests/main" --git-url "ssh://git@git.fnox.se:7999/fo/infra.git" --git-branch "feature/gitmachine"

func (m *Master) Run(ctx context.Context) error {
	m.webserver = webserver.New(m.WsPort)
	go m.webserver.Start(ctx)

	return m.run(ctx)
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

	manifestCh := make(chan types.Machine)
	go func() {
		/* TODO */
		for {
			select {
			case manifest := <-manifestCh:
				fmt.Println(manifest.Host)
				fmt.Println(manifest.IP)
				// TODO template most string values to support secrets?
				b, err := json.Marshal(manifest)
				if err != nil {
					logrus.Error(err)
					continue
				}
				err = m.webserver.Websocket.BroadcastFilter(b, func(s *melody.Session) bool {
					if host, exists := s.Get("host"); exists && host.(string) != manifest.Host {
						return false
					}
					if a, exists := s.Get("allowed"); exists && a.(bool) {
						return true
					}
					return false
				})
				if err != nil {
					logrus.Error(err)
					continue
				}
				// mSessions, err := m.webserver.Websocket.Sessions()
				// if err != nil {
				// 	logrus.Error(err)
				// 	continue
				// }
				//
				// for _, sess := range mSessions {
				//
				// }
			case <-ctx.Done():
				return
			}
		}
	}()

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

	// TODO context timeout here.
}

func (m *Master) clone(ctx context.Context, authOpts *git.AuthOptions, cloneOpts repository.CloneOptions, manifestCh chan types.Machine) error {
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

	log.Println("clone")

	commit, err := gitClient.Clone(ctx, m.GitURL, cloneOpts)
	if err != nil {
		return err
	}
	log.Println("cloned", commit)

	files, err := os.ReadDir(filepath.Join(dir, m.GitPath))

	for _, file := range files {
		machine := types.Machine{}
		path := filepath.Join(dir, m.GitPath, file.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			logrus.Errorf("error opening: %s err: %s", path, err)
			continue
		}

		err = yaml.Unmarshal(b, &machine)
		if err != nil {
			logrus.Errorf("error yaml parse: %s err: %s", path, err)
			continue
		}
		manifestCh <- machine
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
