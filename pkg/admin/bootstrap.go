package admin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func (a *Admin) Bootstrap(ctx context.Context, hosts []string) error {
	conf, err := a.config()
	if err != nil {
		return err
	}

	binaryPath, err := GetSelfLocation()
	if err != nil {
		return err
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return err
	}

	master := conf.FindMasterForConnection(ctx, "", "")

	if master == "" {
		return fmt.Errorf("found no alive master")
	}

	agentClient := agent.NewClient(conn)
	for _, host := range hosts {

		logrus.Infof("Copying %s to %s on %s", binaryPath, a.targetPath, host)

		// find where own binary is located
		// SCP binary to target
		// ssh to target and start binary with --one-shot
		// (do we need to wait that it shows up in pending list?)
		// call /api/machines/accept-v1 with {"host":hostname} body

		// it will configure it-self from git and then die and start itself with systemd.
		config := &ssh.ClientConfig{
			User: a.sshUser,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeysCallback(agentClient.Signers),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		err := sshCommands(ctx, config, host, binaryPath, a.targetPath, master, a.zone)
		if err != nil {
			return err
		}
	}
	return nil
}

func sshCommands(ctx context.Context, config *ssh.ClientConfig, host, src, dstFolder, master, zone string) error {
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		return err
	}
	defer client.Close()
	err = copyFileToServer(client, src, "/tmp") // always save in /tmp and mv to correct location
	if err != nil {
		return err
	}

	// TODO if we are not allowd sudo wihout PW write it to stdin?
	// hostIn, err := session.StdinPipe()
	// if err != nil {
	// 	return err
	// }
	// fmt.Fprint(os.Stderr, "Enter Password: ")

	// golangci-lint says unnecessary conversion (unconvert) on this line. This is not unnecessary. Only works on windows if its this ways.
	// pw, err := term.ReadPassword(int(syscall.Stdin))
	// if err != nil {
	// 	return err
	// }
	// fmt.Println()
	// err = session.Start(cmd)
	// if err != nil {
	// 	return err
	// }

	// _, err = hostIn.Write(pw)
	// if err != nil {
	// 	return err
	// }

	// return nil
	dst := filepath.Join(dstFolder, filepath.Base(src))
	err = runOverSSH(ctx, client, fmt.Sprintf("sudo mv %s %s", filepath.Join("/tmp", filepath.Base(src)), dst))
	if err != nil {
		return err
	}

	// TODO start goroutine here that checks for the server to appear in API and need accept! then accept

	err = runOverSSH(ctx, client, fmt.Sprintf("sudo %s agent --one-shot --master %s --zone %s", dst, master, zone))
	if err != nil {
		return err
	}

	return nil
}

func runOverSSH(ctx context.Context, client *ssh.Client, cmd string) error {
	logrus.Infof("ssh: %s", cmd)
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	// session.Stdout = os.Stdout
	defer session.Close()
	// buf := &bytes.Buffer{} // TODO do we want io.MultiWriter aswell?
	// buf2 := &bytes.Buffer{}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	err = session.Start(cmd)
	if err != nil {
		return fmt.Errorf("ssh: error running command %s error: %w", cmd, err)
		// return fmt.Errorf("%w stdout: %s stderr: %s", err, buf.String(), buf2.String())
	}

	exit := make(chan struct{}, 1)
	defer close(exit)

	//TODO stream session.Stdout and session.Stderr and print in own goroutine?

	go func() {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				// fmt.Println("stdout", buf.String(), "stderr", buf2.String())
				session.Signal(ssh.SIGINT)
				session.Close()
			}
		case <-exit:
		}
	}()

	err = session.Wait()
	if err != nil {
		// return fmt.Errorf("%w stdout: %s stderr: %s", err, buf.String(), buf2.String())
		return fmt.Errorf("ssh: error waiting for command %s error: %w", cmd, err)
	}

	return nil
}

func copyFileToServer(client *ssh.Client, src, dst string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}

	defer session.Close()

	file, err := os.Open(src)
	if err != nil {
		return err
	}

	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return err
	}

	stdoutBuf := bytes.Buffer{}
	stderrBuf := bytes.Buffer{}
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	hostIn, err := session.StdinPipe()
	if err != nil {
		return err
	}

	err = session.Start("/usr/bin/scp -t " + dst)
	if err != nil {
		return err
	}

	fmt.Fprintf(hostIn, "C0755 %d %s\n", stat.Size(), filepath.Base(src))
	_, err = io.Copy(hostIn, file)
	if err != nil {
		return fmt.Errorf("%w stdout: %s stderr: %s", err, stdoutBuf.String(), stderrBuf.String())
	}

	fmt.Fprint(hostIn, "\x00")
	hostIn.Close()

	return session.Wait()
}
func GetSelfLocation() (string, error) {
	fname, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "", err
	}
	return filepath.Abs(fname)
}
