package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/websocket"
	"github.com/sirupsen/logrus"
)

// TODO use this config to persist token on disk
// make sure its permission is 600.
type Config struct {
	Masters Masters `json:"masters"`
	Token   string  `json:"token"`
}

type Masters []Master

func (m *Config) FindMasterForConnection(ctx context.Context) string {
	for {
		for _, master := range m.Masters {
			masters, err := master.isAlive()
			if err != nil {
				logrus.Error("master not alive:", err)
				continue
			}
			// TODO set new master list here.
			m.Masters = masters
			return string(master)
		}
		if ctx.Err() != nil {
			return ""
		}

		logrus.Error("found no working master will sleep 10 seconds and try again")
		delay := time.NewTimer(time.Second * 10)
		select {
		case <-delay.C:
		case <-ctx.Done():
			if !delay.Stop() {
				<-delay.C
			}
			return ""
		}
	}
}

type Master string

func (m Master) isAlive() (Masters, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u, err := websocket.ToHTTP(string(m))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	data := &struct {
		Masters Masters
	}{}

	err = json.NewDecoder(resp.Body).Decode(data)
	if err != nil {
		return nil, err
	}

	// Save the new config to configfile
	return data.Masters, nil
}

func FromFile(path string) (*Config, error) {
	c := &Config{}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	err = json.NewDecoder(f).Decode(c)
	return c, err
}

func ToFile(path string, config *Config) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(config)
}
