package webserver

import (
	"encoding/json"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
)

type WebsocketMessage struct {
	Type string
	Body json.RawMessage
}

func (wm WebsocketMessage) MachineUpdate() (types.Machine, error) {
	machine := types.Machine{}
	err := json.Unmarshal(wm.Body, &machine)
	return machine, err
}
