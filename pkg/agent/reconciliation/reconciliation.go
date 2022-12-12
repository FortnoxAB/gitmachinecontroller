package reconciliation

import (
	"fmt"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

type MachineReconciler struct {
	restartUnits map[string]string
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

	return mr.Systemd(machine.Systemd)
}

// Only yum for now.
func (mr *MachineReconciler) packages(packages types.Packages) error {
	for _, pkg := range packages {
		name := pkg.Name + "-" + pkg.Version
		if pkg.Version == "*" {
			name = pkg.Name
		}
		out, errStr, err := runCommand(fmt.Sprintf("yum install %s", name))
		if err != nil {
			logrus.Error(out, errStr, err)
		}
	}
	return nil
}

func (mr *MachineReconciler) Systemd(systemd types.SystemdUnits) error {
	return nil
}
