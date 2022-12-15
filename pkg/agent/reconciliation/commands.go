package reconciliation

import (
	"fmt"

	"github.com/fortnoxab/gitmachinecontroller/pkg/agent/command"
	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

func (mr *MachineReconciler) commands(commands types.Commands) error {
	for _, cmd := range commands {
		// command.Command
		// command.Check

		_, _, err := command.Run(cmd.Check) // dont run command if check did not exit 0
		if err != nil {
			continue
		}

		// TODO report errors back to master or with local metrics?
		stdOut, stdErr, err := command.Run(cmd.Command)
		if err != nil {
			logrus.Error(err)
			continue
		}
		fmt.Println("stdout", stdOut)
		fmt.Println("stderr", stdErr)
	}
	return nil
}
