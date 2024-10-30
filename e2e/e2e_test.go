package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/agent"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/config"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master"
	"github.com/stretchr/testify/assert"
)

func initMasterAgent(t *testing.T) (*master.Master, *agent.Agent, func()) {
	master := &master.Master{
		GitURL:          "https://test/gitrepo",
		GitPollInterval: time.Minute,
		WsPort:          "9876",
		Masters: config.Masters{
			{
				URL:  "http://localhost:9876",
				Zone: "zone1",
			},
		},
	}
	agent := agent.NewAgent("./agentConfig")
	agent.Master = "http://localhost:9876"
	agent.Hostname = "mycooltestagent"
	return master, agent, func() {
		os.Remove("./agentConfig")
	}
}

func TestMasterAgentAccept(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	master, agent, closer := initMasterAgent(t)
	defer closer()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := master.Run(ctx)
		assert.NoError(t, err)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := agent.Run(ctx)
		assert.NoError(t, err)
	}()

	client := NewAuthedHttpClient(t, "http://localhost:9876")
	resp, err := client.Get("/machines")
	assert.NoError(t, err)
	body := getBody(t, resp.Body)
	assert.Contains(t, body, "acceptHost('mycooltestagent')")
	assert.Contains(t, body, ">Accept<")

	resp, err = client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)
	body = getBody(t, resp.Body)
	fmt.Println("accept resp", body)

	time.Sleep(200 * time.Millisecond)
	resp, err = client.Get("/machines")
	assert.NoError(t, err)
	body = getBody(t, resp.Body)
	assert.NotContains(t, body, ">Accept<")

	resp, err = client.Get("/api/machines-v1")
	assert.NoError(t, err)
	body = getBody(t, resp.Body)
	assert.Contains(t, body, `"name":"mycooltestagent"`)
	assert.Contains(t, body, `"ip":"127.0.0.1"`)
	assert.Contains(t, body, `"Online":true`)
	assert.Contains(t, body, `"Accepted":true`)
	assert.Contains(t, body, `"Git":false`)

	cancel()
	wg.Wait()
}

type authedHttpClient struct {
	token   string
	baseURL string
}

func NewAuthedHttpClient(t *testing.T, baseURL string) *authedHttpClient {
	type tokenStruct struct {
		Jwt string
	}

	time.Sleep(200 * time.Millisecond)
	resp, err := http.Post("http://localhost:9876/api/admin-v1", "application/json", nil)
	assert.NoError(t, err)
	defer resp.Body.Close()

	token := &tokenStruct{}
	err = json.NewDecoder(resp.Body).Decode(token)
	assert.NoError(t, err)

	fmt.Println("my token is", token.Jwt)
	return &authedHttpClient{
		token:   token.Jwt,
		baseURL: baseURL,
	}
}

func (ahc *authedHttpClient) Post(u string, body io.Reader) (resp *http.Response, err error) {
	u = strings.TrimLeft(u, "/")

	req, err := http.NewRequest(http.MethodPost, ahc.baseURL+"/"+u, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", ahc.token)

	return http.DefaultClient.Do(req)
}
func (ahc *authedHttpClient) Get(u string) (resp *http.Response, err error) {
	u = strings.TrimLeft(u, "/")

	req, err := http.NewRequest(http.MethodGet, ahc.baseURL+"/"+u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", ahc.token)

	return http.DefaultClient.Do(req)
}

func getBody(t *testing.T, b io.ReadCloser) string {

	d, err := io.ReadAll(b)
	assert.NoError(t, err)
	return string(d)
}
