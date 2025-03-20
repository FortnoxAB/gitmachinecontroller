package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/admin"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/secrets"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMasterAgentAccept(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

	resp, err := c.client.Get("/machines")
	assert.NoError(t, err)
	body := getBody(t, resp.Body)
	assert.Contains(t, body, "acceptHost('mycooltestagent')")
	assert.Contains(t, body, ">Accept<")

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	c.waitForAccepted()
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
	t.Cleanup(func() {
		os.Remove("./gitrepo/mycooltestagent.yml")
		os.Remove("/tmp/test.systemd")
		os.Remove("/tmp/testfromurl")
	})
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
  tasks:
    - commands: []
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
        version: '*'
`, ts.URL)

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

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

	c.waitForAccepted()

	// make sure we fetched file from http server with sha256 hash
	var content []byte
	WaitFor(t, time.Second*3, "wait for file", func() bool {
		content, err = os.ReadFile("/tmp/testfromurl")
		return len(content) != 0
	})
	assert.NoError(t, err)
	assert.EqualValues(t, "the file content", content)

	content, err = os.ReadFile("/tmp/test.systemd")
	assert.NoError(t, err)
	assert.EqualValues(t, "filecontentishere\n", content)

	time.Sleep(time.Second * 1)
	cancel()
	c.wg.Wait()
}

func TestMasterAgentGitOpsWithLock(t *testing.T) {
	t.Cleanup(func() {
		os.Remove("./gitrepo/mycooltestagent.yml")
		os.Remove("/tmp/test.systemd")
		os.Remove("/tmp/testfromurl")
	})
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  tasks:
    - name: install cool service
      lock:
        key: cool-service
        ttl: 10m
      commands:
        - command: touch /tmp/test
      files:
      - content: |
          filecontentishere
        path: /tmp/test.systemd
        systemd:
          action: restart
          name: exporter_exporter
          daemonreload: true
`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

	c.commander.Mock.On("Run", "systemctl restart exporter_exporter").Return("", "", nil).Once()
	c.commander.Mock.On("Run", "systemctl daemon reload").Return("", "", nil).Once()
	c.commander.Mock.On("Run", "touch /tmp/test").Return("", "", nil).Twice()

	c.redis.On("SetNX", mock.Anything, "gmc.lockcool-service", "mycooltestagent", time.Minute*10).
		Return(redis.NewBoolResult(true, nil)).
		Twice()

	c.redis.On("Del", mock.Anything, "gmc.lockcool-service").
		Return(redis.NewIntResult(1, nil)).
		Twice()

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	c.waitForAccepted()

	var content []byte
	WaitFor(t, time.Second*3, "wait for file", func() bool {
		content, err = os.ReadFile("/tmp/test.systemd")
		return len(content) != 0
	})
	assert.NoError(t, err)
	assert.EqualValues(t, "filecontentishere\n", content)

	time.Sleep(time.Second)
	cancel()
	c.wg.Wait()
}

func TestCliCommand(t *testing.T) {
	os.Setenv("NO_COLOR", "true")
	t.Cleanup(func() {
		os.Remove("./gitrepo/mycooltestagent.yml")
		os.Remove("./adminConfig")
	})
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

	c.commander.Mock.On("RunWithCode", "uptime").Return(" 14:43:12 up 56 days, 23:56,  1 user,  load average: 0,71, 0,58, 0,46", "", 0, nil).Once()

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)

	c.waitForAccepted()

	err = os.WriteFile("./adminConfig", []byte(fmt.Sprintf(`
		{"masters":[{"name":"https://127.0.0.1:%s","zone":"zone1"}],
		"token":"%s"}`, c.master.WsTLSPort, c.client.Token)), 0666)
	assert.NoError(t, err)

	stdout := captureStdout()

	a := admin.NewAdmin("./adminConfig", "", "", admin.WithTLSConfig(trustCert("./cert.pem")))
	err = a.Exec(context.TODO(), "uptime")
	assert.NoError(t, err)

	out := stdout()
	assert.Contains(t, out, " 14:43:12 up 56 days, 23:56,  1 user,  load average: 0,71, 0,58, 0,46")
	assert.Contains(t, out, "mycooltestagent:")

	cancel()
	c.wg.Wait()
}

func TestCliCommandInvalidToken(t *testing.T) {
	t.Cleanup(func() {
		os.Remove("./gitrepo/mycooltestagent.yml")
		os.Remove("./adminConfig")
	})
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)
	c.waitForAccepted()

	err = os.WriteFile("./adminConfig", []byte(fmt.Sprintf(`
		{"masters":[{"name":"https://127.0.0.1:%s","zone":"zone1"}],
		"token":"%s"}`, c.master.WsTLSPort, "blaha")), 0666)
	assert.NoError(t, err)

	buf := &bytes.Buffer{}
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors: true,
	})
	logrus.SetOutput(buf)
	a := admin.NewAdmin("./adminConfig", "", "", admin.WithTLSConfig(trustCert("./cert.pem")))
	err = a.Exec(context.TODO(), "uptime")
	assert.Equal(t, "websocket: bad handshake", err.Error())

	assert.Contains(t, buf.String(), "http_request_status=401")
	cancel()
	c.wg.Wait()
}

func TestCliCommandNotAdminToken(t *testing.T) {
	t.Cleanup(func() {
		os.Remove("./gitrepo/mycooltestagent.yml")
	})
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  ip: 127.0.0.1`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)
	c.waitForAccepted()

	buf := &bytes.Buffer{}
	logrus.SetOutput(buf)
	a := admin.NewAdmin("./agentConfig", "", "", admin.WithTLSConfig(trustCert("./cert.pem")))
	err = a.Exec(context.TODO(), "uptime")
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "run-command-request permission denied")

	cancel()
	c.wg.Wait()
}
func TestCliApply(t *testing.T) {
	t.Cleanup(func() {
		os.Remove("./gitrepo/mycooltestagent.yml")
		os.Remove("./newfile.txt")
		os.Remove("./adminConfig")
		os.Remove("./newspec.yml")
	})
	machineYaml := `apiVersion: gitmachinecontroller.io/v1beta1
metadata:
  annotations:
    feature: ihavecoolfeature
  labels:
    os: rocky9
    type: server
  name: mycooltestagent
spec:
  tasks:
    - files:
      - content: |
          itsfromgit
        path: newfile.txt
  ip: 127.0.0.1`

	err := os.WriteFile("./gitrepo/mycooltestagent.yml", []byte(machineYaml), 0666)
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

	_, err = c.client.Post("/api/machines/accept-v1", bytes.NewBufferString(`{"host":"mycooltestagent"}`))
	assert.NoError(t, err)
	c.waitForAccepted()

	err = os.WriteFile("./adminConfig", []byte(fmt.Sprintf(`
		{"masters":[{"name":"https://127.0.0.1:%s","zone":"zone1"}],
		"token":"%s"}`, c.master.WsTLSPort, c.client.Token)), 0666)
	assert.NoError(t, err)

	var content []byte
	WaitFor(t, 2*time.Second, "file to have content from git", func() bool {
		content, err = os.ReadFile("./newfile.txt")
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
  tasks:
    - files:
      - content: |
          filecontentishere
        path: newfile.txt
  lines: []`

	err = os.WriteFile("./newspec.yml", []byte(applyMachineYaml), 0666)
	assert.NoError(t, err)

	stdout := captureStdout()

	a := admin.NewAdmin("./adminConfig", "", "", admin.WithTLSConfig(trustCert("./cert.pem")))
	err = a.Apply(ctx, []string{"newspec.yml"})
	assert.NoError(t, err)

	out := stdout()
	assert.Contains(t, out, "apply file:  newspec.yml")

	WaitFor(t, 2*time.Second, "file to have content from apply", func() bool {
		content, err = os.ReadFile("./newfile.txt")
		assert.NoError(t, err)
		return string(content) == "filecontentishere\n"
	})
	assert.EqualValues(t, "filecontentishere\n", content)

	//sleep here and see that git doesnt overwrite it
	time.Sleep(2 * time.Second)
	content, err = os.ReadFile("./newfile.txt")
	assert.NoError(t, err)
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

	WaitFor(t, 2*time.Second, "file to have content from git again", func() bool {
		content, err = os.ReadFile("./newfile.txt")
		assert.NoError(t, err)
		return string(content) == "itsfromgit\n"
	})
	assert.EqualValues(t, "itsfromgit\n", content)

	cancel()
	c.wg.Wait()
}

func TestMasterEncryptString(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	c := initMasterAgent(t, ctx)

	resp, err := c.client.Post("/api/secret-encrypt-v1", bytes.NewBufferString(`mysecretstring`))
	assert.NoError(t, err)
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	sh := secrets.NewHandler("asdfasdf")
	files := types.Files{
		{
			Content: fmt.Sprintf(`my cool test file content with {{secret "%s"}}`, string(b)),
		},
	}
	err = sh.DecryptFilesContent(files)
	assert.NoError(t, err)

	assert.Equal(t, "my cool test file content with mysecretstring", files[0].Content)
	cancel()
	c.wg.Wait()
}
