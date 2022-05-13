package command

import (
	"ctrace/config"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
)

var configCmd = &cli.Command{
	Name:  "config",
	Usage: "set ctrace config",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "set",
			Usage: "set config item",
		},

		&cli.StringFlag{
			Name:  "unset",
			Usage: "unset config item",
		},
	},
	Action: func(ctx *cli.Context) error {
		if ctx.NArg() > 0 {
			return fmt.Errorf("key does not has a section: %s\n", ctx.Args().First())
		}
		c, err := config.GetConfigFromYml()
		if err != nil {
			return err
		}
		if ctx.String("set") != "" {
			configStr := ctx.String("set")
			strs := strings.Split(configStr, "=")
			if len(strs) < 2 {
				return fmt.Errorf("key does not has a section: %s\n", strs)
			}
			key, value := strs[0], strs[1]
			if err := config.UpdateConfig(key, []byte(value), c); err != nil {
				return fmt.Errorf("config update failed: %v\n", err)
			}
			return nil
		}
		if ctx.String("unset") != "" {
			key := ctx.String("unset")
			if err := config.UpdateConfig(key, nil, c); err != nil {
				return fmt.Errorf("config update failed: %v\n", err)
			}
			return nil
		}
		return config.PrintConfig(c)
	},
}
