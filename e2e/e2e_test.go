package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/admin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestMasterAgentAccept(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c, closer := initMasterAgent(t, ctx)
	defer closer()

	resp, err := c.client.Get("/machines")
	assert.NoError(t, err)
	body := getBody(t, resp.Body)
	assert.Contains(t, body, "acceptHost('mycooltestagent')")
	assert.Contains(t, body, ">Accept<")

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
	resp, err = c.client.Get("/machines")
	assert.NoError(t, err)
	body = getBody(t, resp.Body)
	assert.NotContains(t, body, ">Accept<")

	resp, err = c.client.Get("/api/machines-v1")
	assert.NoError(t, err)
	body = getBody(t, resp.Body)
	assert.Contains(t, body, `"name":"mycooltestagent"`)
	assert.Contains(t, body, `"ip":"127.0.0.1"`)
	assert.Contains(t, body, `"Online":true`)
	assert.Contains(t, body, `"Accepted":true`)
	assert.Contains(t, body, `"Git":false`)

	cancel()
	c.wg.Wait()
}
func TestMasterAgentGitOps(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "the file content")
	}))
	defer ts.Close()
	machineYaml := fmt.Sprintf(`apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  commands: []
  files:
  - checksum: 9b76e7ea790545334ea524f3ca33db8eb6c4541a9b476911e5abf850a566b41c
    path: /tmp/testfromurl
    url: %s
  - content: |
      filecontentishere
    path: /tmp/test.systemd
    systemd:
      action: restart
      name: exporter_exporter
      daemonreload: true
  ip: 10.81.22.150
  lines: []
  packages:
  - name: vim-enhanced
    version: '*'
  - name: mycoolpackage
    version: '*'`, ts.URL)

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)
	defer os.Remove("./gitrepo/mycooltestagent.yml")
	defer os.Remove("/tmp/test.systemd")
	defer os.Remove("/tmp/testfromurl")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c, closer := initMasterAgent(t, ctx)
	defer closer()

	c.commander.Mock.On("Run", "systemctl restart exporter_exporter").Return("", "", nil).Once()
	c.commander.Mock.On("Run", "systemctl daemon reload").Return("", "", nil).Once()

	// return 0 means its already installed
	c.commander.Mock.On("RunExpectCodes", "rpm -q vim-enhanced", 0, 1).Return("", 0, nil).Twice()

	// return 1 means its not installed yet and we'll try to install it
	c.commander.Mock.On("RunExpectCodes", "rpm -q mycoolpackage", 0, 1).Return("", 1, nil).Twice()
	c.commander.Mock.On("Run", "rpm -q --whatprovides mycoolpackage").Return("mycoolpackage", "", nil).Twice()
	c.commander.Mock.On("Run", "yum install -y mycoolpackage").Return("", "", nil).Twice()

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	time.Sleep(2 * time.Second)

	// make sure we fetched file from http server with sha256 hash
	content, err := os.ReadFile("/tmp/testfromurl")
	assert.NoError(t, err)
	assert.EqualValues(t, "the file content", content)

	content, err = os.ReadFile("/tmp/test.systemd")
	assert.NoError(t, err)
	assert.EqualValues(t, "filecontentishere\n", content)

	cancel()
	c.wg.Wait()
}

func TestCliCommand(t *testing.T) {
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1
  lines: []`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)
	defer os.Remove("./gitrepo/mycooltestagent.yml")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c, closer := initMasterAgent(t, ctx)
	defer closer()

	c.commander.Mock.On("RunWithCode", "uptime").Return(" 14:43:12 up 56 days, 23:56,  1 user,  load average: 0,71, 0,58, 0,46", "", 0, nil).Once()

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	time.Sleep(2 * time.Second)

	err = os.WriteFile("./adminConfig", []byte(fmt.Sprintf(`
		{"masters":[{"name":"http://localhost:%s","zone":"zone1"}],
		"token":"%s"}`, c.master.WsPort, c.client.Token)), 0666)
	assert.NoError(t, err)
	defer os.Remove("./adminConfig")

	stdout := captureStdout()

	a := admin.NewAdmin("./adminConfig", "", "")
	err = a.Exec(context.TODO(), "uptime")
	assert.NoError(t, err)

	out := stdout()
	assert.Contains(t, out, " 14:43:12 up 56 days, 23:56,  1 user,  load average: 0,71, 0,58, 0,46")
	assert.Contains(t, out, "mycooltestagent:")

	cancel()
	c.wg.Wait()
}

func TestCliCommandInvalidToken(t *testing.T) {
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1
  lines: []`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)
	defer os.Remove("./gitrepo/mycooltestagent.yml")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c, closer := initMasterAgent(t, ctx)
	defer closer()

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	time.Sleep(2 * time.Second)

	err = os.WriteFile("./adminConfig", []byte(fmt.Sprintf(`
		{"masters":[{"name":"http://localhost:%s","zone":"zone1"}],
		"token":"%s"}`, c.master.WsPort, "blaha")), 0666)
	assert.NoError(t, err)
	defer os.Remove("./adminConfig")

	buf := &bytes.Buffer{}
	logrus.SetOutput(buf)
	a := admin.NewAdmin("./adminConfig", "", "")
	err = a.Exec(context.TODO(), "uptime")
	assert.Equal(t, "websocket: bad handshake", err.Error())

	assert.Contains(t, buf.String(), "Error #01: auth: error validating")
	cancel()
	c.wg.Wait()
}

func TestCliCommandNotAdminToken(t *testing.T) {
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1
  lines: []`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)
	defer os.Remove("./gitrepo/mycooltestagent.yml")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c, closer := initMasterAgent(t, ctx)
	defer closer()

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	time.Sleep(2 * time.Second)

	buf := &bytes.Buffer{}
	logrus.SetOutput(buf)
	a := admin.NewAdmin("./agentConfig", "", "")
	err = a.Exec(context.TODO(), "uptime")
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "run-command-request permission denied")

	cancel()
	c.wg.Wait()
}
func TestCliApply(t *testing.T) {
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  files:
  - content: |
      itsfromgit
    path: newfile.txt
  ip: 127.0.0.1
  lines: []`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)
	defer os.Remove("./gitrepo/mycooltestagent.yml")
	defer os.Remove("./newfile.txt")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c, closer := initMasterAgent(t, ctx)
	defer closer()

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = os.WriteFile("./adminConfig", []byte(fmt.Sprintf(`
		{"masters":[{"name":"http://localhost:%s","zone":"zone1"}],
		"token":"%s"}`, c.master.WsPort, c.client.Token)), 0666)
	assert.NoError(t, err)
	defer os.Remove("./adminConfig")

	var content string
	WaitFor(t, 1*time.Second, "file to have content from git", func() bool {
		content, err = getFileContent("./newfile.txt")
		return err == nil
	})
	assert.EqualValues(t, "itsfromgit\n", content)

	applyMachineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
    gmc.io/ignore: "true"
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1
  files:
  - content: |
      filecontentishere
    path: newfile.txt
  lines: []`

	err = os.WriteFile("./newspec.yml", []byte(applyMachineYaml), 0666)
	assert.NoError(t, err)
	defer os.Remove("./newspec.yml")

	stdout := captureStdout()

	a := admin.NewAdmin("./adminConfig", "", "")
	err = a.Apply(ctx, []string{"newspec.yml"})
	assert.NoError(t, err)

	out := stdout()
	assert.Contains(t, out, "apply file:  newspec.yml")

	WaitFor(t, 1*time.Second, "file to have content from apply", func() bool {
		content, err = getFileContent("./newfile.txt")
		assert.NoError(t, err)
		return content == "filecontentishere\n"
	})
	assert.EqualValues(t, "filecontentishere\n", content)

	applyMachineYaml = `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1
  files:
  - content: |
      filecontentishere
    path: newfile.txt
  lines: []`

	err = os.WriteFile("./newspec.yml", []byte(applyMachineYaml), 0666)
	assert.NoError(t, err)

	err = a.Apply(ctx, []string{"newspec.yml"})
	assert.NoError(t, err)

	WaitFor(t, 1*time.Second, "file to have content from git again", func() bool {
		content, err = getFileContent("./newfile.txt")
		assert.NoError(t, err)
		return content == "itsfromgit\n"
	})
	assert.EqualValues(t, "itsfromgit\n", content)

	cancel()
	c.wg.Wait()
}
