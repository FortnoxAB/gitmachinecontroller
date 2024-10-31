package reconciliation

import (
	"fmt"

	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/command"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

type MachineReconciler struct {
	restartUnits       map[string]string
	daemonReloadNeeded bool
	commander          command.Commander
}

func NewMachineReconciler(c command.Commander) *MachineReconciler {
	return &MachineReconciler{commander: c}
}

func (mr *MachineReconciler) Reconcile(machine *types.Machine) error {
	mr.restartUnits = make(map[string]string) // map[unit]action

	err := mr.commands(machine.Spec.Commands)
	if err != nil {
		return err
	}

	err = mr.files(machine.Spec.Files)
	if err != nil {
		return err
	}
	err = mr.lines(machine.Spec.Lines)
	if err != nil {
		return err
	}
	err = mr.packages(machine.Spec.Packages)
	if err != nil {
		return err
	}

	return mr.runSystemdTriggers()
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
	if mr.daemonReloadNeeded {
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
