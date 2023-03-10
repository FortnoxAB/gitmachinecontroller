package command

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/shlex"
)

func Run(command string) (string, string, error) {
	stdout, stderr, _, err := RunWithCode(command)
	return stdout, stderr, err
}
func RunWithCode(command string) (string, string, int, error) {
	args, err := shlex.Split(command)
	if err != nil {
		return "", "", -1, err
	}
	cmd := exec.Command(args[0], args[1:]...) // #nosec
	outBuf := &strings.Builder{}
	errBuf := &strings.Builder{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	err = cmd.Run()
	code := cmd.ProcessState.ExitCode()
	if err != nil {
		return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), code, err
	}
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), code, nil
}

func RunExpectCodes(command string, codes ...int) (string, int, error) {
	args, err := shlex.Split(command)
	if err != nil {
		return "", 1, err
	}
	cmd := exec.Command(args[0], args[1:]...) // #nosec
	outBuf := &strings.Builder{}
	errBuf := &strings.Builder{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	err = cmd.Run()
	for _, code := range codes {
		if cmd.ProcessState.ExitCode() == code {
			return strings.TrimSpace(outBuf.String()), code, nil
		}
	}
	if err != nil {
		return strings.TrimSpace(outBuf.String()), cmd.ProcessState.ExitCode(), fmt.Errorf("error running: %s error: %w stderr: %s stdout: %s", command, err, strings.TrimSpace(errBuf.String()), strings.TrimSpace(outBuf.String()))
	}

	return strings.TrimSpace(outBuf.String()), cmd.ProcessState.ExitCode(), fmt.Errorf("error running: %s, did not find expeceted return code", command)
}
