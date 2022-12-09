package types

type Machine struct {
	Commands  Commands          `json:"commands"`
	Files     Files             `json:"files"`
	Host      string            `json:"host"`
	IP        string            `json:"ip"`
	Labels    map[string]string `json:"labels"`
	Lines     Lines             `json:"lines"`
	Pkgs      []string          `json:"pkgs"`
	Provision Provision         `json:"provision"`
	Systemd   SystemdUnits      `json:"systemd"`
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
type Commands []Command

type File struct {
	Path string `json:"path"`
	// supports sha256sum and sha512sum by charcount?
	Checksum string           `json:"checksum"`
	Systemd  SystemdReference `json:"systemd,omitempty"`
	URL      string           `json:"url,omitempty"`
}

type Files []File

type SystemdReference struct {
	// TODO type here
	Action string `json:"action"`
	Name   string `json:"name"`
}

type Line struct {
	Path    string `json:"path"`
	Regexp  string `json:"regexp"`
	Content string `json:"content"`
}
type Lines []Command

type Provision struct {
	Cpus   int `json:"cpus"`
	Memory int `json:"memory"`
	// TODO disks etc..
	// Type   string `json:"type"` // dont need this unless we have multiple Provision providers. but we could use label selectors instead?
}
