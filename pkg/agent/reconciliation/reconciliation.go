package reconciliation

import (
	"fmt"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

type MachineReconciler struct {
	restartUnits       map[string]string
	daemonReloadNeeded bool
}

func (mr *MachineReconciler) Reconcile(machine *types.Machine) error {
	mr.restartUnits = make(map[string]string) // map[unit]action

	err := mr.commands(machine.Commands)
	if err != nil {
		return err
	}

	err = mr.files(machine.Files)
	if err != nil {
		return err
	}
	err = mr.lines(machine.Lines)
	if err != nil {
		return err
	}
	err = mr.packages(machine.Packages)
	if err != nil {
		return err
	}

	return mr.runSystemdTriggers()
}

// Only yum for now.
func (mr *MachineReconciler) packages(packages types.Packages) error {
	for _, pkg := range packages {
		name := pkg.Name + "-" + pkg.Version
		if pkg.Version == "*" {
			name = pkg.Name
		}
		out, errStr, err := runCommand(fmt.Sprintf("yum install -y %s", name))
		if err != nil {
			logrus.Error(out, errStr, err)
		}
	}
	return nil
}

func (mr *MachineReconciler) unitNeedsTrigger(systemd *types.SystemdReference) {
	if systemd == nil {
		return
	}
	mr.restartUnits[systemd.Name] = systemd.Action
	if systemd.DaemonReload {
		mr.daemonReloadNeeded = true
	}
}

func (mr *MachineReconciler) runSystemdTriggers() error {
	if mr.daemonReloadNeeded {
		_, _, err := runCommand("systemctl daemon reload")
		if err != nil {
			return err
		}
	}
	for name, action := range mr.restartUnits {
		_, _, err := runCommand(fmt.Sprintf("systemctl %s %s", action, name))
		if err != nil {
			return err
		}
	}
	return nil
}
