/*
   Copyright (C) nerdctl authors.
   Copyright (C) containerd authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/AkihiroSuda/nerdctl/pkg/idutil"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/errdefs"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var killCommand = &cli.Command{
	Name:      "kill",
	Usage:     "Kill one or more running containers",
	ArgsUsage: "[flags] CONTAINER [CONTAINER, ...]",
	Action:    killAction,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "signal",
			Aliases: []string{"s"},
			Usage:   "Signal to send to the container",
			Value:   "KILL",
		},
	},
}

func killAction(clicontext *cli.Context) error {
	killSignal := clicontext.String("signal")
	if !strings.HasPrefix(killSignal, "SIG") {
		killSignal = "SIG" + killSignal
	}

	signal, err := containerd.ParseSignal(killSignal)
	if err != nil {
		return err
	}

	if clicontext.NArg() == 0 {
		return errors.Errorf("requires at least 1 argument")
	}

	client, ctx, cancel, err := newClient(clicontext)
	if err != nil {
		return err
	}
	defer cancel()

	argIDs := clicontext.Args().Slice()

	return idutil.WalkContainers(ctx, client, argIDs, func(ctx context.Context, client *containerd.Client, shortID, ID string) error {
		if err := killContainer(ctx, clicontext, client, shortID, ID, signal); err != nil {
			if errdefs.IsNotFound(err) {
				fmt.Fprintf(clicontext.App.ErrWriter, "Error response from daemon: Cannot kill container: %s: No such container: %s\n", shortID, shortID)
				os.Exit(1)
			}
			return err
		}
		_, err := fmt.Fprintf(clicontext.App.Writer, "%s\n", shortID)
		return err
	})
}

func killContainer(ctx context.Context, clicontext *cli.Context, client *containerd.Client, shortID, id string, signal syscall.Signal) error {
	container, err := client.LoadContainer(ctx, id)
	if err != nil {
		return err
	}

	task, err := container.Task(ctx, cio.Load)
	if err != nil {
		return err
	}

	status, err := task.Status(ctx)
	if err != nil {
		return err
	}

	paused := false

	switch status.Status {
	case containerd.Created, containerd.Stopped:
		fmt.Fprintf(clicontext.App.ErrWriter, "Error response from daemon: Cannot kill container: %s: Container %s is not running\n", shortID, shortID)
		os.Exit(1)
	case containerd.Paused, containerd.Pausing:
		paused = true
	default:
	}

	if err := task.Kill(ctx, signal); err != nil {
		return err
	}

	// signal will be sent once resume is finished
	if paused {
		if err := task.Resume(ctx); err != nil {
			logrus.Warnf("Cannot unpause container %s: %s", shortID, err)
		}
	}
	return nil
}