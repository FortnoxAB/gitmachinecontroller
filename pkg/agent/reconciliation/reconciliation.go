package reconciliation

import (
	"fmt"

	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/command"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/protocol"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/fortnoxab/gitmachinecontroller/pkg/websocket"
	"github.com/sirupsen/logrus"
)

type MachineReconciler struct {
	restartUnits       map[string]string
	daemonReloadNeeded bool
	commander          command.Commander
	wsClient           websocket.Websocket
}

func NewMachineReconciler(c command.Commander, wsClient websocket.Websocket) *MachineReconciler {
	return &MachineReconciler{
		commander: c,
		wsClient:  wsClient,
	}
}

func (mr *MachineReconciler) Reconcile(machine *types.Machine) error {
	mr.restartUnits = make(map[string]string) // map[unit]action

	for _, task := range machine.Spec.Tasks {
		clear(mr.restartUnits) // reset on each task run

		if task.Lock != nil {
			msg, _ := protocol.NewMessage("agent-aqure-lock", task.Lock)
			response, err := mr.wsClient.WriteAndWait(msg)
			if err != nil {
				logrus.Errorf("error aquire lock: %s", err)
				continue
			}

			if response.Type != "agent-aqured-lock" {
				logrus.Info("failed to aquire lock: ", task.Lock.Key)
				continue
			}
		}

		mr.commands(task.Commands)
		mr.files(task.Files)
		mr.lines(task.Lines)
		mr.packages(task.Packages)

		err := mr.runSystemdTriggers()
		if err != nil {
			logrus.Errorf("error running systemd: %s", err)
		}
		if task.Lock != nil {
			msg, _ := protocol.NewMessage("agent-release-lock", task.Lock)
			err := mr.wsClient.WriteJSON(msg)
			if err != nil {
				logrus.Errorf("error aquire lock: %s", err)
				continue
			}
			// no need to wait for response here
		}
	}

	return nil
}

func (mr *MachineReconciler) unitNeedsTrigger(systemd *types.SystemdReference) {
	if systemd == nil {
		return
	}
	logrus.Debug("unitNeedsTrigger", fmt.Sprintf("%#v", systemd))
	mr.restartUnits[systemd.Name] = systemd.Action
	if systemd.DaemonReload {
		mr.daemonReloadNeeded = true
	}
}

func (mr *MachineReconciler) runSystemdTriggers() error {
	if mr.daemonReloadNeeded && len(mr.restartUnits) > 0 {
		_, _, err := mr.commander.Run("systemctl daemon reload")
		if err != nil {
			return err
		}
	}
	for name, action := range mr.restartUnits {
		_, _, err := mr.commander.Run(fmt.Sprintf("systemctl %s %s", action, name))
		if err != nil {
			return err
		}
	}
	return nil
}
