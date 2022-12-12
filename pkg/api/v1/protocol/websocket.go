package protocol

import (
	"encoding/json"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
)

type WebsocketMessage struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
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

func NewMachineUpdate(machine *types.Machine) ([]byte, error) {
	b, err := json.Marshal(machine)
	if err != nil {
		return nil, err
	}

	msg := WebsocketMessage{
		Type: "machine-update",
		Body: b,
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
