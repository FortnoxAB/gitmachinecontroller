package e2e_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/mocks"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/config"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type testWrapper struct {
	client    *authedHttpClient
	master    *master.Master
	agent     *agent.Agent
	commander *mocks.MockCommander
	wg        *sync.WaitGroup
}

func initMasterAgent(t *testing.T, ctx context.Context) (testWrapper, func()) {

	logrus.SetLevel(logrus.DebugLevel)
	port, err := freePort()
	assert.NoError(t, err)
	portStr := strconv.Itoa(port)
	master := &master.Master{
		GitURL:          "https://test/gitrepo",
		GitPollInterval: time.Second,
		WsPort:          portStr,
		JWTKey:          "asdfasdf",
		Masters: config.Masters{
			{
				URL:  "http://localhost:" + portStr,
				Zone: "zone1",
			},
		},
	}
	mockedCommander := mocks.NewMockCommander(t)
	agent := agent.NewAgent("./agentConfig", mockedCommander)
	agent.Master = "http://localhost:" + portStr
	agent.Hostname = "mycooltestagent"

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := master.Run(ctx)
		assert.NoError(t, err)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(200 * time.Millisecond)
		err := agent.Run(ctx)
		assert.NoError(t, err)
	}()

	time.Sleep(400 * time.Millisecond)
	client := NewAuthedHttpClient(t, "http://localhost:"+portStr)
	return testWrapper{
			client:    client,
			master:    master,
			agent:     agent,
			commander: mockedCommander,
			wg:        wg,
		}, func() {
			os.Remove("./agentConfig")
		}
}
func freePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			port := l.Addr().(*net.TCPAddr).Port
			l.Close()
			return port, nil
		}
	}
	return
}

func captureStdout() func() string {
	old := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	return func() string {
		w.Close()
		os.Stdout = old // restoring the real stdout
		return <-outC
	}
}
func captureStderr() func() string {
	old := os.Stderr // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stderr = w

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	return func() string {
		w.Close()
		os.Stderr = old // restoring the real stdout
		return <-outC
	}
}