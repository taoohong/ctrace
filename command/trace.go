package command

import (
	"ctrace/config"
	"ctrace/ctrace"
	"fmt"

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
			Name:    "exclude-event",
			Aliases: []string{"ee"},
			Value:   nil,
			Usage:   "exclude an event from being traced. use this flag multiple times to choose multiple events to exclude",
		},
		&cli.StringSliceFlag{
			Name:  "comm",
			Value: nil,
			Usage: "only trace events from comm command. Example: trace --comm ls,sh",
		},
		&cli.StringSliceFlag{
			Name:    "exclude-comm",
			Aliases: []string{"ecomm"},
			Value:   nil,
			Usage:   "don't trace events from comm command. Example: trace -ecomm ls,sh",
		},
		&cli.StringSliceFlag{
			Name:  "set",
			Value: nil,
			Usage: "field 'set' selects a set of events to trace according to predefined sets.",
		},
		&cli.StringSliceFlag{
			Name:    "exclude-set",
			Aliases: []string{"eset"},
			Value:   nil,
			Usage:   "field 'exclude-set' selects a set of events not to trace according to predefined sets.",
		},
		&cli.BoolFlag{
			Name:    "relative-time",
			Aliases: []string{"rt"},
			Value:   false,
			Usage:   "to get the monotonic time since tracee was started",
		},
		&cli.Int64Flag{
			Name:    "trace-time",
			Aliases: []string{"t"},
			Value:   0,
			Usage:   "[Unit:second]specify the time to trace the container and output the seccomp configuration file. ",
		},
		&cli.BoolFlag{
			Name:    "seccomp",
			Aliases: []string{"s"},
			Value:   false,
			Usage:   "trace container and generate seccomp profile",
		},
	},

	Subcommands: []*cli.Command{
		listSubCmd,
	},

	Action: func(ctx *cli.Context) error {
		if ctx.IsSet("event") && ctx.IsSet("exclude-event") {
			return fmt.Errorf("'event' and 'exclude-event' can't be used in parallel")
		}
		if ctx.IsSet("comm") && ctx.IsSet("exclude-comm") {
			return fmt.Errorf("'comm' and 'exclude-comm' can't be used in parallel")
		}
		if ctx.IsSet("set") && ctx.IsSet("exclude-set") {
			return fmt.Errorf("'set' and 'exclude-set' can't be used in parallel")
		}
		conf, err := config.GetConfigFromYml()
		if err != nil {
			return err
		}
		cfg := ctrace.CtraceConfig{
			OutputFormat:   string(conf.OutputFormat),
			PerfBufferSize: int(conf.PerfBufferSize),
			EventsPath:     string(conf.EventsPath),
			ErrorsPath:     string(conf.ErrorsPath),
			RelativeTime:   ctx.Bool("relative-time"),
			TraceTime:      ctx.Int64("trace-time"),
			Seccomp:        ctx.Bool("seccomp"),
		}

		filter := ctrace.Filter{
			CommFilter: &ctrace.StringFilter{
				Equal:    []string{},
				NotEqual: []string{},
			},
			EventsToTrace: []int32{},
		}
		eventFilter := &ctrace.StringFilter{Equal: []string{}, NotEqual: []string{}}
		setFilter := &ctrace.StringFilter{Equal: []string{}, NotEqual: []string{}}

		eventsNameToID := make(map[string]int32, len(ctrace.EventsIDToEvent))
		for _, event := range ctrace.EventsIDToEvent {
			eventsNameToID[event.Name] = event.ID
		}

		for _, e := range ctx.StringSlice("event") {
			eventFilter.Enabled = true
			eventFilter.Equal = append(eventFilter.Equal, e)
		}
		for _, ne := range ctx.StringSlice("exclude-event") {
			eventFilter.Enabled = true
			eventFilter.NotEqual = append(eventFilter.NotEqual, ne)
		}
		for _, c := range ctx.StringSlice("comm") {
			filter.CommFilter.Enabled = true
			filter.CommFilter.Equal = append(filter.CommFilter.Equal, c)
		}
		for _, nc := range ctx.StringSlice("exclude-comm") {
			filter.CommFilter.Enabled = true
			filter.CommFilter.NotEqual = append(filter.CommFilter.NotEqual, nc)
		}
		for _, s := range ctx.StringSlice("set") {
			setFilter.Enabled = true
			setFilter.Equal = append(setFilter.Equal, s)
		}
		for _, ns := range ctx.StringSlice("exclude-set") {
			setFilter.Enabled = true
			setFilter.NotEqual = append(setFilter.NotEqual, ns)
		}
		filter.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
		if err != nil {
			return err
		}
		cfg.Filter = &filter
		t, err := ctrace.New(cfg)
		if err != nil {
			return fmt.Errorf("error creating Ctrace: %v", err)
		}
		return t.Run()
	},
}

func prepareEventsToTrace(eventFilter *ctrace.StringFilter, setFilter *ctrace.StringFilter, eventsNameToID map[string]int32) ([]int32, error) {
	eventFilter.Enabled = true
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

	var res []int32
	setsToEvents := make(map[string][]int32)
	isExcluded := make(map[int32]bool)
	for id, event := range ctrace.EventsIDToEvent {
		// 通过这种方式拿到每种set对应的事件id
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
		}
	}
	for _, name := range excludeEvents {
		id, ok := eventsNameToID[name]
		if !ok {
			return nil, fmt.Errorf("invalid event to exclude: %s", name)
		}
		isExcluded[id] = true
	}
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	res = make([]int32, 0, len(ctrace.EventsIDToEvent))
	for _, name := range eventsToTrace {
		id, ok := eventsNameToID[name]
		if !ok {
			return nil, fmt.Errorf("invalid event to trace: %s", name)
		}
		res = append(res, id)
	}
	for _, set := range setsToTrace {
		setEvents, ok := setsToEvents[set]
		if !ok {
			return nil, fmt.Errorf("invalid set to trace: %s", set)
		}
		for _, id := range setEvents {
			if !isExcluded[id] {
				res = append(res, id)
			}
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
			c.GetContainers()
			// fmt.Println(c.GetContainers())
		}
		return nil
	},
}
