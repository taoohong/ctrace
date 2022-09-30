package command

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"
)

var Commands = []*cli.Command{
	configCmd,
	traceCmd,
	// more subcommands ...
}

var GlobalOptions = []cli.Flag{}

// ErrPrintAndExit 表示遇到需要打印信息并提前退出的情形，不需要打印错误信息
var ErrPrintAndExit = errors.New("print and exit")

// global action
var GlobalAction = func(ctx *cli.Context) error {
	if ctx.NArg() == 0 && ctx.NumFlags() == 0 {
		return fmt.Errorf("ctrace needs command to run")
	}
	cli.ShowAppHelp(ctx)
	return nil
}
