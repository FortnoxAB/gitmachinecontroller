package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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

	master := conf.FindMasterForConnection(ctx, "")

	u, err := websocket.ToWS(master)
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
					if cnt == 0 {
						logrus.Error("found no machines online on master")
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
				if cmdRes.Online {
					green := color.New(color.FgGreen).SprintFunc()
					fmt.Printf("%s:\n%s\n\n", green(msg.From), cmdRes.Stdout)
				} else {
					red := color.New(color.FgRed).SprintFunc()
					fmt.Printf("%s (offline):\n%s\n\n", red(msg.From), cmdRes.Stdout)
				}

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

	// find where own binary is located
	// SCP binary to target
	// ssh to target and start binary with --one-shot
	// (do we need to wait that it shows up in pending list?)
	// call /api/machines/accept-v1 with {"host":hostname} body

	// it will configure it-self from git and then die and start itself with systemd.

	fmt.Println(conf)
	return nil
}
func (a *Admin) Proxy(ctx context.Context) error {
	conf, err := a.config()
	if err != nil {
		return err
	}

	target, err := url.Parse(conf.FindMasterForConnection(ctx, ""))
	target.RawQuery = ""
	target.Path = ""

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.Header.Set("Authorization", conf.Token)
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			logrus.Infof("proxy to %s", req.URL.String())
		},
	}
	srv := &http.Server{
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           proxy,
	}
	go func() {
		port := 8080
		for {
			srv.Addr = ":" + strconv.Itoa(port)
			logrus.Infof("listening on https://%s", srv.Addr)
			if err := listenAndServe(srv); err != nil && !errors.Is(err, http.ErrServerClosed) {
				if isErrorAddressAlreadyInUse(err) {
					logrus.Errorf("error starting proxy: %s", err)
					port++
					continue
				}
				logrus.Fatalf("error starting webserver %s", err)
			}
		}
	}()
	<-ctx.Done()
	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShutDown); !errors.Is(err, http.ErrServerClosed) && err != nil {
		logrus.Error(err)
	}

	return nil
}
func (a *Admin) config() (*config.Config, error) {
	conf, err := config.FromFile(a.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			conf = &config.Config{
				Masters: config.Masters{config.Master("replace me")},
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

// openBrowser opens a link in the correct browser depending on OS.
func openBrowser(link string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = Run("xdg-open", link)
	case "darwin":
		err = Run("open", link)
	case "windows":
		err = Run("rundll32", "url.dll,FileProtocolHandler", link)
	default:
		return errors.New("Unknown operating system, dont know how to open the link in the browser")
	}
	return err
}

// Run runs a command.
func Run(head string, parts ...string) error {
	var err error

	cmd := exec.Command(head, parts...) // #nosec
	cmd.Env = os.Environ()

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("run %s %s error: %w ", head, strings.Join(parts, " "), err)
	}
	return nil
}

func isErrorAddressAlreadyInUse(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	const WSAEADDRINUSE = 10048
	if runtime.GOOS == "windows" && errErrno == WSAEADDRINUSE {
		return true
	}
	return false
}

func listenAndServe(srv *http.Server) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	logrus.Infof("started proxy on http://%s", ln.Addr().String())
	openBrowser("http://" + ln.Addr().String() + "/machines")
	return srv.Serve(ln)
}
