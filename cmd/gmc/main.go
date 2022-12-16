package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fortnoxab/gitmachinecontroller/pkg/admin"
	"github.com/fortnoxab/gitmachinecontroller/pkg/agent"
	"github.com/fortnoxab/gitmachinecontroller/pkg/master"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Version is application version.
var (
	Version     = "dev"
	BuildTime   = ""
	BuildCommit = ""
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM)
	defer stop()
	err := app().RunContext(ctx, os.Args)
	if err != nil {
		logrus.Error(err)
		os.Exit(1)
	}
}

func app() *cli.App {
	app := cli.NewApp()
	app.Name = "gmc"
	app.Usage = "gitmachinecontroller, control fleets of VMs or machines."
	app.Version = fmt.Sprintf(`Version: "%s", BuildTime: "%s", Commit: "%s"`, Version, BuildTime, BuildCommit)
	app.Before = globalBefore
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "available levels are: " + strings.Join(getLevels(), ","),
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:  "agent",
			Usage: "starts the agent that controls a machine and make sure its in the desired configured state.",
			Action: func(c *cli.Context) error {
				agent := agent.NewAgentFromContext(c)
				return agent.Run(c.Context)
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "master",
					Usage: "which master to connect to. Will connect to masters and get all of them and persist to config if set.",
				},
				&cli.StringFlag{
					Name:    "config",
					Aliases: []string{"c"},
					Value:   "/etc/gmc/agent.json",
					Usage:   "config file location",
				},
				&cli.BoolFlag{
					Name:  "one-shot",
					Value: false,
					Usage: "runs a single sync and then exists 0. Used for bootstrapping itself",
				},
				&cli.BoolFlag{
					Name:  "dry", // can be used together with one-shot do dry run a bootstrap.
					Value: false,
					Usage: "only print what would have been changed.",
				},
				&cli.StringFlag{
					Name:  "fake-hostname",
					Usage: "Used for testing purpuses instead of checking hostname with os.Hostname()",
				},
				// masters fetch and push over websocket
				// &cli.DurationFlag{
				// 	Name:  "poll-interval",
				// 	Value: time.Minute,
				// 	Usage: "How often do we sync from the masters.",
				// },
			},
		},
		{
			Name:  "master",
			Usage: "starts the master that syncs from git and decodes secrets.",
			Action: func(c *cli.Context) error {
				master := master.NewMasterFromContext(c)
				return master.Run(c.Context)
			},
			Flags: []cli.Flag{
				&cli.StringSliceFlag{
					Name:  "master",
					Usage: "which masters to advertise when using HA.",
				},
				&cli.StringFlag{
					Name:  "git-url",
					Usage: "",
				},
				&cli.StringFlag{
					Name:  "git-branch",
					Usage: "",
				},
				&cli.StringFlag{
					Name:  "git-path",
					Usage: "",
				},
				&cli.StringFlag{
					Name:  "git-user",
					Usage: "",
				},
				&cli.StringFlag{
					Name:  "git-identity-path",
					Usage: "path to private key file",
				},
				&cli.StringFlag{
					Name:  "git-identity-passphrase",
					Usage: "passphrase for the private key",
				},
				&cli.StringFlag{
					Name:  "git-known-hosts-path",
					Usage: "path to known hosts file",
				},
				&cli.DurationFlag{
					Name:  "git-poll-interval",
					Value: time.Minute,
					Usage: "How often do we sync from the masters.",
				},
				&cli.StringFlag{
					Name:  "secret-key",
					Usage: "used to decrypt secrets in the git repo with template function.",
				},
				&cli.StringFlag{
					Name:  "jwt-key",
					Usage: "used to sign the jwt's",
				},
				&cli.StringFlag{
					Name:  "port",
					Value: "8080",
					Usage: "webserver port to listen to",
				},
			},
		},
		{
			Name:  "exec",
			Usage: "executes an adhoc command on multiple machines.",
			Action: func(c *cli.Context) error {
				if c.Args().Len() != 1 {
					return fmt.Errorf(`expected arg as one string. Example gmc exec "cat /etc/hosts"`)
				}
				admin := admin.NewAdminFromContext(c)
				return admin.Exec(c.Context, c.Args().First())
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					// this is the client for SREs so it needs to have a config somewhere.
					Name:    "config",
					Aliases: []string{"c"},
					Value:   defaultConfigLocation(),
					Usage:   "config file location. contains info about the master urls",
				},
				&cli.StringFlag{
					Name:    "selector",
					Aliases: []string{"l"},
					Usage:   "filter machines on, supports '=', '==', and '!='.(e.g. -l os=rhel,key2=value2)",
				},
				&cli.StringFlag{
					Name:    "regexp",
					Aliases: []string{"r"},
					Usage:   "filter machine by regexp on hostname.",
				},
				&cli.BoolFlag{
					Name:  "dry",
					Value: false,
					Usage: "only pring on which machines the command would have been run on.",
				},
			},
		},
		{
			Name:  "apply",
			Usage: `applies a directory of manifests to hosts. Useful for local development. Will be overridden by git source if not annotated with gcm.io/ignore="true"`,
			Action: func(c *cli.Context) error {
				admin := admin.NewAdminFromContext(c)
				return admin.Apply(c.Context)
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					// this is the client for SREs so it needs to have a config somewhere.
					Name:    "config",
					Aliases: []string{"c"},
					Value:   defaultConfigLocation(),
					Usage:   "config file location. contains info about the master urls",
				},
				&cli.StringFlag{
					Name:    "selector",
					Aliases: []string{"l"},
					Usage:   "filter machines on, supports '=', '==', and '!='.(e.g. -l os=rhel,key2=value2)",
				},
				&cli.StringFlag{
					Name:    "regexp",
					Aliases: []string{"r"},
					Usage:   "filter machine by regexp on hostname.",
				},
				&cli.BoolFlag{
					Name:  "dry",
					Value: false,
					Usage: "only pring on which machines the command would have been run on.",
				},
			},
		},
		{
			Name:  "bootstrap",
			Usage: "installs the agent on a new machine.",
			Action: func(c *cli.Context) error {
				admin := admin.NewAdminFromContext(c)
				return admin.Bootstrap(c.Context)
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					// this is the client for SREs so it needs to have a config somewhere.
					Name:    "config",
					Aliases: []string{"c"},
					Value:   defaultConfigLocation(),
					Usage:   "config file location. contains info about the master urls",
				},
				&cli.StringFlag{
					// this is the client for SREs so it needs to have a config somewhere.
					Name:  "location",
					Value: "/usr/local/bin",
					Usage: "where to put the gmc binary when bootstrapping",
				},
				&cli.BoolFlag{
					Name:  "dry",
					Value: false,
					Usage: "run the agent in --dry mode",
				},
			},
		},
		{
			Name:  "proxy",
			Usage: "proxies to master with admin JWT if it exists in config",
			Action: func(c *cli.Context) error {
				admin := admin.NewAdminFromContext(c)
				return admin.Proxy(c.Context)
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					// this is the client for SREs so it needs to have a config somewhere.
					Name:    "config",
					Aliases: []string{"c"},
					Value:   defaultConfigLocation(),
					Usage:   "config file location. contains info about the master urls",
				},
			},
		},
		{
			Name:  "completion",
			Usage: "generate completion for shells",
			Subcommands: []*cli.Command{
				{
					Name:   "bash",
					Usage:  "put in .bashrc: 'source <(" + os.Args[0] + " completion bash)'",
					Action: bashCompletion,
				},
				{
					Name:   "zsh",
					Usage:  "put in .zshrc: 'source <(" + os.Args[0] + " completion zsh)'",
					Action: bashCompletion,
				},
			},
		},
	}
	return app
}

func defaultConfigLocation() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not find user home directory: %s", err)
	}
	return filepath.Join(dir, ".config", "gmc.json")
}

func globalBefore(c *cli.Context) error {
	lvl, err := logrus.ParseLevel(c.String("log-level"))
	if err != nil {
		return err
	}
	if lvl != logrus.InfoLevel {
		fmt.Fprintf(os.Stderr, "using loglevel: %s\n", lvl.String())
	}
	logrus.SetLevel(lvl)
	return nil
}

func bashCompletion(c *cli.Context) error {
	binaryName := os.Args[0]
	script := fmt.Sprintf(`#!/bin/bash

_cli_bash_autocomplete() {
  if [[ "${COMP_WORDS[0]}" != "source" ]]; then
    local cur opts base
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    if [[ "$cur" == "-"* ]]; then
      opts=$( ${COMP_WORDS[@]:0:$COMP_CWORD} ${cur} --generate-bash-completion )
    else
      opts=$( ${COMP_WORDS[@]:0:$COMP_CWORD} --generate-bash-completion )
    fi
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
  fi
}

complete -o bashdefault -o default -o nospace -F _cli_bash_autocomplete %s
`, binaryName)
	fmt.Printf(script)
	// fmt.Println(os.Args)
	return nil
}

func zshCompletion(c *cli.Context) error {
	binaryName := os.Args[0]
	script := fmt.Sprintf(`#!/bin/zsh

_cli_zsh_autocomplete() {
  local -a opts
  local cur
  cur=${words[-1]}
  if [[ "$cur" == "-"* ]]; then
    opts=("${(@f)$(${words[@]:0:#words[@]-1} ${cur} --generate-bash-completion)}")
  else
    opts=("${(@f)$(${words[@]:0:#words[@]-1} --generate-bash-completion)}")
  fi

  if [[ "${opts[1]}" != "" ]]; then
    _describe 'values' opts
  else
    _files
  fi
}

compdef _cli_zsh_autocomplete %s
`, binaryName)
	fmt.Printf(script)
	// fmt.Println(os.Args)
	return nil
}
func getLevels() []string {
	lvls := make([]string, len(logrus.AllLevels))
	for k, v := range logrus.AllLevels {
		lvls[k] = v.String()
	}
	return lvls
}
