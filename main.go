package main

import (
	"ctrace/command"
	"fmt"
	"log"
	"os"

	"github.com/syndtr/gocapability/capability"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                   "ctrace",
		Usage:                  "Trace containers using eBPF",
		Version:                "v0.0.1",
		UseShortOptionHandling: true,
		Flags:                  command.GlobalOptions,
		Action:                 command.GlobalAction,
		Commands:               command.Commands,
	}
	if !isCapable() {
		log.Fatal("Not enough privileges to run this program")
	}

	err := app.Run(os.Args)
	if err != nil && err != command.ErrPrintAndExit {
		log.Fatal(err)
	}
}

func isCapable() bool {
	c, err := capability.NewPid2(0)
	if err != nil {
		fmt.Println("Current user capabilities could not be retrieved. Assure running with enough privileges")
		return true
	}
	err = c.Load()
	if err != nil {
		fmt.Println("Current user capabilities could not be retrieved. Assure running with enough privileges")
		return true
	}

	return c.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN)
}

