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
	if err != nil {
		return outBuf.String(), errBuf.String(),
			fmt.Errorf("error running: %s error: %w stderr: %s stdout: %s", command, err, errBuf.String(), outBuf.String())
	}
	return outBuf.String(), errBuf.String(), err
}

func runCommandCode(command string) (int, error) {
	args, err := shlex.Split(command)
	if err != nil {
		return 1, err
	}
	cmd := exec.Command(args[0], args[1:]...) // #nosec
	outBuf := &strings.Builder{}
	errBuf := &strings.Builder{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	err = cmd.Run()
	if err != nil {
		return cmd.ProcessState.ExitCode(), fmt.Errorf("error running: %s error: %w stderr: %s stdout: %s", command, err, errBuf.String(), outBuf.String())
	}
	return cmd.ProcessState.ExitCode(), err
}
