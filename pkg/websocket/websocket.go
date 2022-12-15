package websocket

import "net/url"

func ToHTTP(master string) (string, error) {
	u, err := url.Parse(master)
	if err != nil {
		return "", err
	}

	if u.Scheme == "ws" {
		u.Scheme = "http"
	}
	if u.Scheme == "wss" {
		u.Scheme = "https"
	}
	u.Path = "/api/up-v1"
	return u.String(), nil
}

func ToWS(master string) (string, error) {
	u, err := url.Parse(master)
	if err != nil {
		return "", err
	}

	if u.Scheme == "http" {
		u.Scheme = "ws"
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	}
	u.Path = "/api/websocket-v1"
	return u.String(), nil
}
