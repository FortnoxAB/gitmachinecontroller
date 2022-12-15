package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/fatih/color"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/config"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/build"
	"github.com/fortnoxab/gitmachinecontroller/pkg/websocket"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// handles exec and apply commands.
type Admin struct {
	// exec and apply
	configFile string
	// labelselector
	selector string
	regexp   string
	dry      bool

	// binary location when Bootstrap
	location string
}

func NewAdminFromContext(c *cli.Context) *Admin {
	fmt.Printf("%#v\n", c.Args().Slice())
	return &Admin{
		configFile: c.String("config"),
		selector:   c.String("selector"),
		regexp:     c.String("regexp"),
		dry:        c.Bool("dry"),
		location:   c.String("location"),
	}
}

func (a *Admin) Exec(ctx context.Context, command string) error {
	conf, err := a.config()
	if err != nil {
		return err
	}
	headers := http.Header{}
	headers.Add("X-VERSION", build.JSON())
	headers.Set("Authorization", conf.Token)

	wsClient := websocket.NewWebsocketClient()
	u, err := websocket.ToWS(conf.Masters[0]) // TODO all masters using "findMasterForConnection"
	if err != nil {
		return err
	}

	err = wsClient.ConnectContext(ctx, u, headers)
	if err != nil {
		return err
	}

	cmdReq := protocol.RunCommandRequest{
		Command:       command,
		LabelSelector: a.selector,
		Regexp:        a.regexp,
	}
	msg, err := protocol.NewMessage("run-command-request", cmdReq)
	if err != nil {
		return err
	}

	reqid := uuid.New().String()
	msg.RequestID = reqid
	msg.Source = "cli"

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		expectedReadCount := 0
		readCount := 0
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-wsClient.Read():
				msg, err := protocol.ParseMessage(data)
				if err != nil {
					logrus.Error("websocket reader:", err)
					continue
				}
				if msg.RequestID != reqid {
					continue
				}
				if msg.Type == "expected-result-count" {
					var cnt int
					err := json.Unmarshal(msg.Body, &cnt)
					if err != nil {
						logrus.Error(err)
						return
					}
					expectedReadCount = cnt
					continue
				}

				if msg.Type != "command-result" {
					logrus.Warnf("got unexpected message of type: %s", msg.Type)
					continue
				}
				readCount++

				cmdRes := &protocol.CommandResult{}
				err = json.Unmarshal(msg.Body, cmdRes)
				if err != nil {
					logrus.Error("error reading command result:", err)
					continue
				}
				green := color.New(color.FgGreen).SprintFunc()
				fmt.Printf("%s:\n%s\n\n", green(msg.From), cmdRes.Stdout)

				if readCount >= expectedReadCount {
					return
				}
			}
		}
	}()

	err = wsClient.WriteJSON(msg)
	if err != nil {
		return err
	}
	wg.Wait()
	return nil
}

func (a *Admin) Apply(ctx context.Context) error {
	conf, err := a.config()
	if err != nil {
		return err
	}

	fmt.Println(conf)
	return nil
}

func (a *Admin) Bootstrap(ctx context.Context) error {
	conf, err := a.config()
	if err != nil {
		return err
	}

	fmt.Println(conf)
	return nil
}
func (a *Admin) config() (*config.Config, error) {
	conf, err := config.FromFile(a.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			conf = &config.Config{
				Masters: []string{"replace me"},
			}
			err := os.MkdirAll(filepath.Dir(a.configFile), 0700)
			if err != nil {
				return nil, err
			}

			err = config.ToFile(a.configFile, conf)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return conf, nil
}
