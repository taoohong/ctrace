package command

import (
	"ctrace/config"
	"ctrace/ctrace"
	"fmt"
	"log"
	"strconv"

	"github.com/urfave/cli/v2"
)

var traceCmd = &cli.Command{
	Name:  "trace",
	Usage: "trace containers",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "event",
			Aliases: []string{"e"},
			Value:   nil,
			Usage:   "trace only the specified event or syscall. use this flag multiple times to choose multiple events",
		},
		&cli.StringSliceFlag{
			Name:  "exclude-event",
			Value: nil,
			Usage: "exclude an event from being traced. use this flag multiple times to choose multiple events to exclude",
		},
	},

	Subcommands: []*cli.Command{
		listSubCmd,
	},

	Action: func(ctx *cli.Context) error {
		if ctx.IsSet("event") && ctx.IsSet("exclude-event") {
			return fmt.Errorf("'event' and 'exclude-event' can't be used in parallel")
		}
		eventsNameToID := make(map[string]int32, len(ctrace.EventsIDToEvent))
		for _, event := range ctrace.EventsIDToEvent {
			eventsNameToID[event.Name] = event.ID
		}
		events, err := prepareEventsToTrace(ctx.StringSlice("event"), ctx.StringSlice("exclude-event"), eventsNameToID)
		if err != nil {
			return err
		}
		conf, err := config.GetConfigFromYml()
		if err != nil {
			return err
		}
		cfg := ctrace.CtraceConfig{
			EventsToTrace:  events,
			OutputFormat:   string(conf.OutputFormat),
			PerfBufferSize: int(conf.PerfBufferSize),
			EventsPath:     string(conf.EventsPath),
			ErrorsPath:     string(conf.ErrorsPath),
		}
		log.Println("ctrace config loaded")
		t, err := ctrace.New(cfg)
		if err != nil {
			return fmt.Errorf("error creating Ctrace: %v", err)
		}
		return t.Run()
	},
}

func prepareEventsToTrace(eventsToTrace []string, excludeEvents []string, eventsNameToID map[string]int32) ([]int32, error) {
	var res []int32
	isExcluded := make(map[int32]bool)

	if eventsToTrace == nil {
		for _, name := range excludeEvents {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to exclude: %s", name)
			}
			isExcluded[id] = true
		}
		res = make([]int32, 0, len(ctrace.EventsIDToEvent))
		for _, event := range ctrace.EventsIDToEvent {
			if !isExcluded[event.ID] {
				res = append(res, event.ID)
			}
		}
	} else {
		res = make([]int32, 0, len(ctrace.EventsIDToEvent))
		for _, name := range eventsToTrace {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to trace: %s", name)
			}
			log.Println("user set event " + name + " id " + strconv.FormatInt(int64(id), 10))
			res = append(res, id)
		}
	}
	return res, nil
}

var listSubCmd = &cli.Command{
	Name:  "ls",
	Usage: "list trace info",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "container",
			Aliases: []string{"c"},
		},
	},
	Action: func(ctx *cli.Context) error {
		if ctx.NumFlags() == 0 {
			return fmt.Errorf("ls need to use with flag")
		}
		if ctx.Bool("container") {
			c := ctrace.InitContainers()
			if err := c.Populate(); err != nil {
				return fmt.Errorf("error initializing containers: %v", err)
			}
			fmt.Println(c.GetContainers())
		}
		return nil
	},
}
