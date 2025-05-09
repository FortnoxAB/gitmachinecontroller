package types

import (
	"os"
	"strconv"
	"time"
)

// ApiVersion is gitmachinecontroller.io/v1beta1.
type Machine struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   *Metadata `json:"metadata"`
	Spec       *Spec     `json:"spec"`
}

type Metadata struct {
	// This is the hostname of the machine
	Name        string      `json:"name"`
	Labels      Labels      `json:"labels"`
	Annotations Annotations `json:"annotations"`
}

type Annotations map[string]string

func (l Annotations) Has(label string) (exists bool) {
	if _, ok := l[label]; ok {
		return true
	}
	return false
}

func (l Annotations) Get(label string) (value string) {
	if val, ok := l[label]; ok {
		return val
	}
	return ""
}

type Labels map[string]string

func (l Labels) Has(label string) (exists bool) {
	if _, ok := l[label]; ok {
		return true
	}
	return false
}

func (l Labels) Get(label string) (value string) {
	if val, ok := l[label]; ok {
		return val
	}
	return ""
}

type Spec struct {
	Tasks     Tasks
	IP        string    `json:"ip"`
	Provision Provision `json:"provision"`
}

type Task struct {
	Name string `json:"name"`
	// Depends on other task to happen before
	Depends string `json:"depends"`

	Commands Commands `json:"commands,omitempty"`
	Files    Files    `json:"files,omitempty"`
	Lines    Lines    `json:"lines,omitempty"`
	Packages Packages `json:"packages,omitempty"`

	Lock *Lock `json:"lock,omitempty"`
}
type Tasks []*Task

type Packages []*Package

type Package struct {
	Name string `json:"name"`

	// Version where "*" means latest
	Version string `json:"version"`
}

type Command struct {
	Command string `json:"command"`
	Check   string `json:"check"`
	//TODO add Shell to specify in what shell to run?
}
type Commands []*Command

type File struct {
	Path string `json:"path"`
	// if URL is archived specify which file to unarchive
	ExtractFile string            `json:"extractFile"`
	ExtractDir  string            `json:"extractDir"`
	Checksum    string            `json:"checksum"`
	Systemd     *SystemdReference `json:"systemd,omitempty"`
	Content     string            `json:"content"`
	URL         string            `json:"url,omitempty"`
	Mode        string            `json:"mode"`
	User        string            `json:"user"`
	Group       string            `json:"group"`
}

func (f File) FileMode() (os.FileMode, error) {
	if f.Mode == "" {
		return os.FileMode(0600), nil // default to this
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

type Lock struct {
	Key         string        `json:"key"`
	GracePeriod time.Duration `json:"gracePeriod"`
	TTL         time.Duration `json:"ttl"`
}

// MachineState is used internall in master to keep track of current state.
type MachineState struct {
	Metadata   *Metadata
	IP         string
	LastUpdate time.Time
}
type MachineStateQuestion struct {
	ReplyCh chan map[string]*MachineState
}
