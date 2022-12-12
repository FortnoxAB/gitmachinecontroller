package reconciliation

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/google/shlex"
	"github.com/sirupsen/logrus"
)

func (mr *MachineReconciler) commands(commands types.Commands) error {
	for _, command := range commands {
		// command.Command
		// command.Check

		_, _, err := runCommand(command.Check) // dont run command if check did not exit 0
		if err != nil {
			continue
		}

		// TODO report errors back to master or with local metrics?
		stdOut, stdErr, err := runCommand(command.Command)
		if err != nil {
			logrus.Error(err)
			continue
		}
		fmt.Println("stdout", stdOut)
		fmt.Println("stderr", stdErr)
	}
	return nil
}
func runCommand(command string) (string, string, error) {
	args, err := shlex.Split(command)
	if err != nil {
		return "", "", err
	}
	cmd := exec.Command(args[0], args[1:]...) // #nosec
	outBuf := &strings.Builder{}
	errBuf := &strings.Builder{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}
