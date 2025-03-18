package authedhttpclient

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type Client struct {
	Token   string
	baseURL string
}

func New(t *testing.T, baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
	}
}

func (ahc *Client) AuthAsAdmin() error {
	type tokenStruct struct {
		Jwt string
	}

	resp, err := http.Post(ahc.baseURL+"/api/admin-v1", "application/json", nil)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	token := &tokenStruct{}
	err = json.NewDecoder(resp.Body).Decode(token)
	if err != nil {
		return err
	}

	ahc.Token = token.Jwt
	return nil
}

func (ahc *Client) Post(u string, body io.Reader) (resp *http.Response, err error) {
	u = strings.TrimLeft(u, "/")

	req, err := http.NewRequest(http.MethodPost, ahc.baseURL+"/"+u, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", ahc.Token)

	return http.DefaultClient.Do(req)
}
func (ahc *Client) Get(u string) (resp *http.Response, err error) {
	u = strings.TrimLeft(u, "/")

	req, err := http.NewRequest(http.MethodGet, ahc.baseURL+"/"+u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", ahc.Token)

	return http.DefaultClient.Do(req)
}
