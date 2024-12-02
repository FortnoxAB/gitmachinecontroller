package protocol

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
)

type Source string

const (
	GitSource    = Source("git")
	ManualSource = Source("manual")
)

type WebsocketMessage struct {
	Type      string          `json:"type"`
	RequestID string          `json:"requestId"`
	Source    Source          `json:"source"`
	From      string          `json:"from"`
	Body      json.RawMessage `json:"body"`
}

func (wm WebsocketMessage) MachineUpdate() (*types.Machine, error) {
	machine := &types.Machine{}
	err := json.Unmarshal(wm.Body, machine)
	return machine, err
}

func NewMessage(t string, body interface{}) (*WebsocketMessage, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	return &WebsocketMessage{
		Type: t,
		Body: json.RawMessage(b),
	}, nil
}
func (wm *WebsocketMessage) Encode() ([]byte, error) {
	return json.Marshal(wm)
}

func NewMachineUpdate(source Source, machine *types.Machine) ([]byte, error) {
	b, err := json.Marshal(machine)
	if err != nil {
		return nil, err
	}

	msg := WebsocketMessage{
		Type:   "machine-update",
		Source: source,
		Body:   b,
	}

	return json.Marshal(msg)
}

func NewMachineAccepted(host, token string) ([]byte, error) {
	msg := WebsocketMessage{
		Type: "machine-accepted",
		Body: []byte(`"` + token + `"`),
	}

	return json.Marshal(msg)
}

func ParseMessage(msg []byte) (*WebsocketMessage, error) {
	data := &WebsocketMessage{}
	err := json.Unmarshal(msg, data)
	return data, err
}

type CommandResult struct {
	Stdout string
	Stderr string
	Err    string
	Online bool
	Code   int
}

func NewCommandResult(requestId string, res *CommandResult) (*WebsocketMessage, error) {
	b, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}

	return &WebsocketMessage{
		Type:      "command-result",
		RequestID: requestId,
		Body:      b,
	}, nil
}

type RunCommandRequest struct {
	Command       string
	LabelSelector string
	Regexp        string
}

type AgentLock struct {
	Key string
	ID  string
	TTL Duration
}

type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(tmp)
		return nil
	default:
		return errors.New("invalid duration")
	}
}
