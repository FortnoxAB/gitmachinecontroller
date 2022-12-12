package types

import (
	"os"
	"strconv"
)

type Machine struct {
	Commands  Commands          `json:"commands"`
	Files     Files             `json:"files"`
	Host      string            `json:"host"`
	IP        string            `json:"ip"`
	Labels    map[string]string `json:"labels"`
	Lines     Lines             `json:"lines"`
	Packages  Packages          `json:"packages"`
	Provision Provision         `json:"provision"`
	Systemd   SystemdUnits      `json:"systemd"`
}

type Packages []*Package

type Package struct {
	Name string
	// * means latest
	Version string
}

type SystemdUnit struct {
	Content string `json:"content"`
	Name    string `json:"name"`
	Path    string `json:"path"`
}

type SystemdUnits []SystemdUnit

type Command struct {
	Command string `json:"command"`
	Check   string `json:"check"`
}
type Commands []*Command

type File struct {
	Path string `json:"path"`
	// if URL is archived specify which file to unarchive
	ExtractFile string           `json:"extractFile"`
	ExtractDir  string           `json:"extractDir"`
	Checksum    string           `json:"checksum"`
	Systemd     SystemdReference `json:"systemd,omitempty"`
	Content     string           `json:"content"`
	URL         string           `json:"url,omitempty"`
	Mode        string           `json:"mode"`
}

func (f File) FileMode() (os.FileMode, error) {
	if f.Mode == "" {
		return os.FileMode(0700), nil // default to this
	}
	u, err := strconv.ParseUint(f.Mode, 8, 32)
	return os.FileMode(u), err
}

type Files []*File

type SystemdReference struct {
	Action       string `json:"action"`
	Name         string `json:"name"`
	DaemonReload bool   `json:"daemonReload"`
}

type Line struct {
	Path    string `json:"path"`
	Regexp  string `json:"regexp"`
	Content string `json:"content"`
}
type Lines []*Line

type Provision struct {
	Cpus   int `json:"cpus"`
	Memory int `json:"memory"`
	// TODO disks etc..
	// Type   string `json:"type"` // dont need this unless we have multiple Provision providers. but we could use label selectors instead?
}
