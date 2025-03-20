package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/mocks"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/config"
	"github.com/fortnoxab/gitmachinecontroller/pkg/authedhttpclient"
	"github.com/fortnoxab/gitmachinecontroller/pkg/httpclient"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type testWrapper struct {
	client          *authedhttpclient.Client
	master          *master.Master
	agent           *agent.Agent
	commander       *mocks.MockCommander
	wg              *sync.WaitGroup
	redis           *mocks.MockCmdable
	waitForAccepted func()
}

func initMasterAgent(t *testing.T, ctx context.Context) testWrapper {
	logrus.SetLevel(logrus.DebugLevel)
	port, err := freePort()
	assert.NoError(t, err)
	portStr := strconv.Itoa(port)
	tlsPortStr := strconv.Itoa(port + 1)
	redisMock := mocks.NewMockCmdable(t)
	master := &master.Master{
		GitURL:          "https://test/gitrepo",
		GitPollInterval: time.Second,
		WsPort:          portStr,
		WsTLSPort:       tlsPortStr,
		TLSCertFile:     "./cert.pem",
		TLSKeyFIle:      "./key.pem",
		JWTKey:          "asdfasdf",
		SecretKey:       "asdfasdf",
		RedisClient:     redisMock,
		Masters: config.Masters{
			{
				URL:  "https://127.0.0.1:" + tlsPortStr,
				Zone: "zone1",
			},
		},
	}
	httpclient.SetTLSConfig(trustCert("./cert.pem"))
	mockedCommander := mocks.NewMockCommander(t)
	agent := agent.NewAgent("./agentConfig", mockedCommander, agent.WithTLSConfig(trustCert("./cert.pem")))
	agent.Master = "https://127.0.0.1:" + tlsPortStr
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
	client := authedhttpclient.New(t, "https://127.0.0.1:"+tlsPortStr)
	err = client.AuthAsAdmin()
	assert.NoError(t, err)

	t.Cleanup(func() {
		os.Remove("./agentConfig")
	})
	return testWrapper{
		client:    client,
		master:    master,
		agent:     agent,
		commander: mockedCommander,
		wg:        wg,
		redis:     redisMock,
		waitForAccepted: func() {
			WaitFor(t, time.Second*2, "wait for accepted", func() bool {
				resp, err := client.Get("/api/machines-v1")
				b := getBody(t, resp.Body)
				return err == nil && strings.Contains(b, `"Accepted":true`) && strings.Contains(b, `"Online":true`)
			})
		},
	}
}

func trustCert(localCertFile string) *tls.Config {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Read in the cert file
	certs, err := os.ReadFile(localCertFile)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", localCertFile, err)
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	return &tls.Config{
		RootCAs: rootCAs,
	}
}

func freePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "127.0.0.1:0"); err == nil {
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

/*
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
*/

func WaitFor(t *testing.T, timeout time.Duration, msg string, ok func() bool) {
	end := time.Now().Add(timeout)
	for {
		if end.Before(time.Now()) {
			t.Errorf("timeout waiting for: %s", msg)
			return
		}
		time.Sleep(10 * time.Millisecond)
		if ok() {
			return
		}
	}
}
