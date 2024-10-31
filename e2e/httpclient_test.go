package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type authedHttpClient struct {
	Token   string
	baseURL string
}

func NewAuthedHttpClient(t *testing.T, baseURL string) *authedHttpClient {
	type tokenStruct struct {
		Jwt string
	}

	resp, err := http.Post(baseURL+"/api/admin-v1", "application/json", nil)
	assert.NoError(t, err)
	defer resp.Body.Close()

	token := &tokenStruct{}
	err = json.NewDecoder(resp.Body).Decode(token)
	assert.NoError(t, err)

	return &authedHttpClient{
		Token:   token.Jwt,
		baseURL: baseURL,
	}
}

func (ahc *authedHttpClient) Post(u string, body io.Reader) (resp *http.Response, err error) {
	u = strings.TrimLeft(u, "/")

	req, err := http.NewRequest(http.MethodPost, ahc.baseURL+"/"+u, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", ahc.Token)

	return http.DefaultClient.Do(req)
}
func (ahc *authedHttpClient) Get(u string) (resp *http.Response, err error) {
	u = strings.TrimLeft(u, "/")

	req, err := http.NewRequest(http.MethodGet, ahc.baseURL+"/"+u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", ahc.Token)

	return http.DefaultClient.Do(req)
}

func getBody(t *testing.T, b io.ReadCloser) string {

	d, err := io.ReadAll(b)
	assert.NoError(t, err)
	return string(d)
}
