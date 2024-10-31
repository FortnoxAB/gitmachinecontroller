package e2e_test

import (
	"context"
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
		time.Sleep(100 * time.Millisecond)
		err := agent.Run(ctx)
		assert.NoError(t, err)
	}()

	time.Sleep(200 * time.Millisecond)
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
