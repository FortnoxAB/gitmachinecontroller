package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

// var client = http.DefaultTransport.(*http.Transport).Clone()
// customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
// client := &http.Client{Transport: customTransport}

var DefaultClient *http.Client

func init() {
	DefaultClient = &http.Client{Timeout: 30 * time.Second}
}

func SetTLSConfig(c *tls.Config) {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = c
	DefaultClient.Transport = customTransport
}
