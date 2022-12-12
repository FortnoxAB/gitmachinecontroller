package config

// TODO use this config to persist token on disk
// make sure its permission is 600.
type Config struct {
	Masters []string
	Token   string
}
