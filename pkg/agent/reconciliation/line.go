package reconciliation

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/fortnoxab/gitmachinecontroller/pkg/api/v1/types"
	"github.com/sirupsen/logrus"
)

func (mr *MachineReconciler) lines(lines types.Lines) error {
	for _, line := range lines {
		err := applyLine(line)
		if err != nil {
			logrus.Errorf("lines: %s: %s", line.Path, err)
			continue
		}
	}
	return nil
}

func applyLine(line *types.Line) error {
	m, err := regexp.Compile(line.Regexp)
	if err != nil {
		return err
	}

	orgFile, err := os.Open(line.Path)
	if err != nil {
		return err
	}
	defer orgFile.Close()

	content, err := io.ReadAll(orgFile)
	if err != nil {
		return err
	}

	stat, err := orgFile.Stat()
	if err != nil {
		return err
	}
	mode := stat.Mode().Perm()
	orgFile.Close()

	tempFile, err := os.CreateTemp(filepath.Dir(line.Path), "gcm")
	if err != nil {
		return err
	}
	defer tempFile.Close()

	newContent := m.ReplaceAll(content, []byte(line.Content))

	if bytes.Equal(content, newContent) {
		return nil // we are already up to date
	}

	_, err = io.Copy(tempFile, bytes.NewBuffer(newContent))
	if err != nil {
		return err
	}
	// TODO think about https://github.com/rancher/rke2/pull/1966/files

	tempFile.Chmod(mode)
	tempFile.Close()
	return os.Rename(tempFile.Name(), line.Path)
}
