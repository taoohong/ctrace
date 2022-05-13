package ctrace

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/template"
)

type eventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats statsStore)
	// Print prints a single event
	Print(event Event)
	// Error prints a single error
	Error(err error)
	// dispose of resources
	Close()
}

func newEventPrinter(kind string, out io.WriteCloser, err io.WriteCloser) (eventPrinter, error) {
	var res eventPrinter
	var initError error
	switch {
	case kind == "table":
		res = &tableEventPrinter{
			out: out,
			err: err,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			out: out,
			err: err,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			out: out,
			err: err,
		}
	}
	initError = res.Init()
	if initError != nil {
		return nil, initError
	}
	return res, nil
}

func newEvent(ctx context, argMetas []ArgMeta, args []interface{}) (Event, error) {
	e := Event{
		Timestamp:       float64(ctx.Ts) / 1000000.0,
		ProcessID:       int(ctx.Pid),
		ThreadID:        int(ctx.Tid),
		ParentProcessID: int(ctx.Ppid),
		UserID:          int(ctx.Uid),
		MountNS:         int(ctx.Mnt_id),
		PIDNS:           int(ctx.Pid_id),
		ProcessName:     string(bytes.TrimRight(ctx.Comm[:], "\x00")),
		HostName:        string(bytes.TrimRight(ctx.Uts_name[:], "\x00")),
		EventID:         int(ctx.Event_id),
		EventName:       EventsIDToEvent[int32(ctx.Event_id)].Name,
		ArgsNum:         int(ctx.Argc),
		ReturnValue:     int(ctx.Retval),
		Args:            make([]Argument, 0, len(args)),
	}
	for i, arg := range args {
		e.Args = append(e.Args, Argument{
			ArgMeta: argMetas[i],
			Value:   arg,
		})
	}
	return e, nil
}

type tableEventPrinter struct {
	ctrace        *Ctrace
	out           io.WriteCloser
	err           io.WriteCloser
	verbose       bool
	containerMode bool
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	fmt.Fprintf(p.out, "%-14s %-6s %-16s %-7s %-7s %-16s %-20s %s", "TIME(s)", "UID", "COMM", "PID", "TID", "RET", "EVENT", "ARGS")
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event Event) {

	fmt.Fprintf(p.out, "%-14f %-6d %-16s %-7d %-7d %-16d %-20s ", event.Timestamp, event.UserID, event.ProcessName, event.ProcessID, event.ThreadID, event.ReturnValue, event.EventName)
	for i, arg := range event.Args {
		if i == 0 {
			fmt.Fprintf(p.out, "%s: %v", arg.Name, arg.Value)
		} else {
			fmt.Fprintf(p.out, ", %s: %v", arg.Name, arg.Value)
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v\n", err)
}

func (p tableEventPrinter) Epilogue(stats statsStore) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "Stats: %+v\n", stats)
}

func (p tableEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

type templateEventPrinter struct {
	ctrace        *Ctrace
	out           io.WriteCloser
	err           io.WriteCloser
	containerMode bool
	templatePath  string
	templateObj   **template.Template
}

func (p *templateEventPrinter) Init() error {
	tmplPath := p.templatePath
	if tmplPath != "" {
		tmpl, err := template.ParseFiles(tmplPath)
		if err != nil {
			return err
		}
		p.templateObj = &tmpl
	} else {
		return errors.New("Please specify a gotemplate for event-based output")
	}
	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Error(err error) {
	fmt.Fprintf(p.err, "%v", err)
}

func (p templateEventPrinter) Print(event Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			p.Error(err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}
}

func (p templateEventPrinter) Epilogue(stats statsStore) {}

func (p templateEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

type jsonEventPrinter struct {
	out io.WriteCloser
	err io.WriteCloser
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		p.Error(err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Error(e error) {
	eBytes, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintln(p.err, string(eBytes))
}

func (p jsonEventPrinter) Epilogue(stats statsStore) {}

func (p jsonEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}

// gobEventPrinter is printing events using golang's builtin Gob serializer
type gobEventPrinter struct {
	out    io.WriteCloser
	err    io.WriteCloser
	outEnc *gob.Encoder
	errEnc *gob.Encoder
}

func (p *gobEventPrinter) Init() error {
	p.outEnc = gob.NewEncoder(p.out)
	p.errEnc = gob.NewEncoder(p.err)
	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		p.Error(err)
	}
}

func (p *gobEventPrinter) Error(e error) {
	_ = p.errEnc.Encode(e)
}

func (p *gobEventPrinter) Epilogue(stats statsStore) {}

func (p gobEventPrinter) Close() {
	p.out.Close()
	p.err.Close()
}
