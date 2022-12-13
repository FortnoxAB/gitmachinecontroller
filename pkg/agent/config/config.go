package config

import (
	"encoding/json"
	"os"
)

// TODO use this config to persist token on disk
// make sure its permission is 600.
type Config struct {
	Masters []string `json:"masters"`
	Token   string   `json:"token"`
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
