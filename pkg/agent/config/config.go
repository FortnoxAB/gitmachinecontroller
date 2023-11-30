package config

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/websocket"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Masters Masters `json:"masters"`
	Token   string  `json:"token"`
	Ignore  bool    `json:"ignore"`
	mutex   sync.RWMutex
}

type Masters []*Master

func (m Masters) string() []string {
	ret := make([]string, len(m))
	for i, a := range m {
		ret[i] = string(a.URL + "#" + a.Zone)
	}
	return ret
}

func (m Masters) Equal(with Masters) bool {
	if len(m) != len(with) {
		return false
	}
	s1 := m.string()
	s2 := with.string()
	sort.Strings(s1)
	sort.Strings(s2)
	for _, m1 := range s1 {
		for _, m2 := range s2 {
			if m1 != m2 {
				return false
			}
		}
	}
	return true
}

func (m *Config) GetMasters() Masters {
	masters := Masters{}
	m.mutex.RLock()
	masters = append(masters, m.Masters...)
	m.mutex.RUnlock()
	return masters
}

// FindMasterForConnection finds a master. If zone is provied its prioritized to use one in our own zone.
func (m *Config) FindMasterForConnection(ctx context.Context, configFile, zone string) string {
	for {

		// prioritize the masters in our own zone.
		masters := m.GetMasters()
		if zone != "" {
			mastersMyZone := Masters{}
			mastersOtherZones := Masters{}
			for _, s := range masters {
				if s.Zone == zone {
					mastersMyZone = append(mastersMyZone, s)
				} else {
					mastersOtherZones = append(mastersOtherZones, s)
				}
				rand.Shuffle(len(mastersMyZone), func(i, j int) {
					mastersMyZone[i], mastersMyZone[j] = mastersMyZone[j], mastersMyZone[i]
				})

				rand.Shuffle(len(mastersOtherZones), func(i, j int) {
					mastersOtherZones[i], mastersOtherZones[j] = mastersOtherZones[j], mastersOtherZones[i]
				})
				masters = append(mastersMyZone, mastersOtherZones...)
			}
			// sort.Slice(masters, func(i, j int) bool {
			// 	return masters[i].Zone == zone
			// })
		} else {
			rand.Shuffle(len(masters), func(i, j int) {
				masters[i], masters[j] = masters[j], masters[i]
			})
		}

		for _, master := range masters {
			masters, err := master.isAlive()
			if err != nil {
				logrus.Errorf("master %s not alive: %s", master.URL, err)
				continue
			}
			if !masters.Equal(m.Masters) {
				m.Masters = masters
				if configFile != "" {
					err := ToFile(configFile, m)
					if err != nil {
						logrus.Errorf("error saving configFile: %s", err)
						// TODO return error instead?
					}
				}
			}
			return master.URL
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

type Master struct {
	URL  string `json:"name"`
	Zone string `json:"zone"`
}

func (m Master) isAlive() (Masters, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u, err := websocket.ToHTTP(string(m.URL))
	if err != nil {
		return nil, err
	}

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
