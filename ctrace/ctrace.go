package ctrace

import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	mapset "github.com/deckarep/golang-set"
	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// CtraceConfig is a struct containing user defined configuration of ctrace
type CtraceConfig struct {
	// EventsToTrace  []int32
	Filter         *Filter
	OutputFormat   string
	PerfBufferSize int
	// BlobPerfBufferSize int
	EventsPath   string
	ErrorsPath   string
	RelativeTime bool
	TraceTime    int64
	Seccomp      bool
}

type Filter struct {
	EventsToTrace []int32
	// UIDFilter     *UintFilter
	// PIDFilter     *UintFilter
	// NewPidFilter  *BoolFilter
	// MntNSFilter   *UintFilter
	// PidNSFilter   *UintFilter
	// UTSFilter     *StringFilter
	CommFilter *StringFilter
	// ContFilter    *BoolFilter
	// NewContFilter *BoolFilter
	// RetFilter     *RetFilter
	// ArgFilter     *ArgFilter
	// Follow        bool
}

type StringFilter struct {
	Equal    []string
	NotEqual []string
	Enabled  bool
}

type counter int32

type statsStore struct {
	eventCounter  counter
	errorCounter  counter
	lostEvCounter counter
	lostWrCounter counter
}

type Ctrace struct {
	config        CtraceConfig
	eventsToTrace map[int32]bool
	bpfModule     *bpf.Module
	eventsPerfMap *bpf.PerfBuffer
	// fileWrPerfMap *bpf.PerfBuffer
	eventsChannel chan []byte
	// fileWrChannel chan []byte
	lostEvChannel chan uint64
	// lostWrChannel chan uint64
	bootTime       uint64
	startTime      uint64
	printer        eventPrinter
	stats          statsStore
	capturedFiles  map[string]int64
	containers     *Containers
	DecParamName   [2]map[argTag]ArgMeta
	EncParamName   [2]map[string]argTag
	SeccompSyscall mapset.Set
}

// context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
type context struct {
	Ts       uint64
	CgroupID uint64
	Pid      uint32
	Tid      uint32
	Ppid     uint32
	HostPid  uint32
	HostTid  uint32
	HostPpid uint32
	Uid      uint32
	Mnt_id   uint32
	Pid_id   uint32
	Comm     [16]byte
	Uts_name [16]byte
	Event_id int32
	Retval   int64
	Argc     uint8
	_        [7]byte
}

func UnameRelease() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return ""
	}
	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}
	ver := string(buf[:])
	if i := strings.Index(ver, "\x00"); i != -1 {
		ver = ver[:i]
	}
	return ver
}

func supportRawTP() (bool, error) {
	ver := UnameRelease()
	if ver == "" {
		return false, fmt.Errorf("could not determine current release")
	}
	ver_split := strings.Split(ver, ".")
	if len(ver_split) < 2 {
		return false, fmt.Errorf("invalid version returned by uname")
	}
	major, err := strconv.Atoi(ver_split[0])
	if err != nil {
		return false, fmt.Errorf("invalid major number: %s", ver_split[0])
	}
	minor, err := strconv.Atoi(ver_split[1])
	if err != nil {
		return false, fmt.Errorf("invalid minor number: %s", ver_split[1])
	}
	if ((major == 4) && (minor >= 17)) || (major > 4) {
		return true, nil
	}
	return false, nil
}

// Validate does static validation of the configuration
func (tc CtraceConfig) Validate() error {
	if tc.Filter.EventsToTrace == nil {
		return fmt.Errorf("eventsToTrace is nil")
	}

	for _, e := range tc.Filter.EventsToTrace {
		if _, ok := EventsIDToEvent[e]; !ok {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
	}

	if tc.OutputFormat != "table" && tc.OutputFormat != "json" && tc.OutputFormat != "gob" {
		return fmt.Errorf("unrecognized output format: %s", tc.OutputFormat)
	}
	return nil
}

func getEBPFProgramPath() (string, error) {
	// if there's a local file, use it
	exePath, err := os.Getwd()
	if err != nil {
		return "", err
	}
	ebpfFilePath := filepath.Join(exePath, "./dist/ctrace.bpf.o")
	_, err = os.Stat(ebpfFilePath)
	if !os.IsNotExist(err) {
		_, err := ioutil.ReadFile(ebpfFilePath)
		return ebpfFilePath, err
	}
	return "", fmt.Errorf("could not find ebpf.o")
}

func (c *counter) Increment(amount ...int) {
	sum := 1
	if len(amount) > 0 {
		sum = 0
		for _, a := range amount {
			sum = sum + a
		}
	}
	atomic.AddInt32((*int32)(c), int32(sum))
}

type eventParam struct {
	encType argType
	encName argTag
}

func (t *Ctrace) initEventsParams() map[int32][]eventParam {
	eventsParams := make(map[int32][]eventParam)
	var seenNames [2]map[string]bool
	var ParamNameCounter [2]argTag
	seenNames[0] = make(map[string]bool)
	ParamNameCounter[0] = argTag(1)
	seenNames[1] = make(map[string]bool)
	ParamNameCounter[1] = argTag(1)
	paramT := noneT
	// 事件ID，事件ArgMeta{name,type}
	for id, params := range EventsIDToParams {
		for _, param := range params {
			switch param.Type {
			case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
				paramT = intT
			case "unsigned int", "u32":
				paramT = uintT
			case "long":
				paramT = longT
			case "unsigned long", "u64":
				paramT = ulongT
			case "off_t":
				paramT = offT
			case "mode_t":
				paramT = modeT
			case "dev_t":
				paramT = devT
			case "size_t":
				paramT = sizeT
			case "void*", "const void*":
				paramT = pointerT
			case "char*", "const char*":
				paramT = strT
			case "const char*const*", "const char**", "char**":
				paramT = strArrT
			case "const struct sockaddr*", "struct sockaddr*":
				paramT = sockAddrT
			default:
				// Default to pointer (printed as hex) for unsupported types
				paramT = pointerT
			}

			// As the encoded parameter name is u8, it can hold up to 256 different names
			// To keep on low communication overhead, we don't change this to u16
			// Instead, use an array of enc/dec maps, where the key is modulus of the event id
			// This can easilly be expanded in the future if required
			if !seenNames[id%2][param.Name] {
				seenNames[id%2][param.Name] = true
				t.EncParamName[id%2][param.Name] = ParamNameCounter[id%2]
				t.DecParamName[id%2][ParamNameCounter[id%2]] = param
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: ParamNameCounter[id%2]})
				ParamNameCounter[id%2]++
			} else {
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: t.EncParamName[id%2][param.Name]})
			}
		}
	}

	if len(seenNames[0]) > 255 || len(seenNames[1]) > 255 {
		panic("Too many argument names given")
	}

	return eventsParams
}

func (t *Ctrace) setStringFilter(filter *StringFilter, filterMapName string, configFilter bpfConfig) error {
	if !filter.Enabled {
		return nil
	}

	filterMap, err := t.bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		err = filterMap.Update([]byte(filter.Equal[i]), filterEqual)
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		err = filterMap.Update([]byte(filter.NotEqual[i]), filterNotEqual)
		if err != nil {
			return err
		}
	}

	bpfConfigMap, err := t.bpfModule.GetMap("config_map")
	if err != nil {
		return err
	}
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		bpfConfigMap.Update(uint32(configFilter), filterIn)
	} else {
		bpfConfigMap.Update(uint32(configFilter), filterOut)
	}

	return nil
}

// TODO populateBPFMaps
func (t *Ctrace) populateBPFMaps() error {
	chosenEventsMap, _ := t.bpfModule.GetMap("chosen_events_map")
	for e, chosen := range t.eventsToTrace {
		// Set chosen events map according to events chosen by the user
		if chosen {
			chosenEventsMap.Update(e, boolToUInt32(true))
		}
	}

	sys32to64BPFMap, _ := t.bpfModule.GetMap("sys_32_to_64_map")
	for _, event := range EventsIDToEvent {
		// Prepare 32bit to 64bit syscall number mapping
		sys32to64BPFMap.Update(event.ID32Bit, event.ID)
	}

	log.Debug("config ready to populated")
	// Initialize config and pids maps
	bpfConfigMap, _ := t.bpfModule.GetMap("config_map")
	bpfConfigMap.Update(uint32(configDetectOrigSyscall), 0)
	bpfConfigMap.Update(uint32(configExecEnv), 0)
	bpfConfigMap.Update(uint32(configStackAddresses), 0)
	bpfConfigMap.Update(uint32(configCaptureFiles), 0)
	bpfConfigMap.Update(uint32(configExtractDynCode), 0)
	bpfConfigMap.Update(uint32(configTraceePid), uint32(os.Getpid()))
	bpfConfigMap.Update(uint32(configCgroupV1), boolToUInt32(t.containers.cgroupV1))

	// Initialize tail calls program array
	// errs := make([]error, 0)
	// errs = append(errs, t.initTailCall(tailVfsWrite, "prog_array", "trace_ret_vfs_write_tail"))
	// errs = append(errs, t.initTailCall(tailVfsWritev, "prog_array", "trace_ret_vfs_writev_tail"))
	// // errs = append(errs, t.initTailCall(tailSendBin, "prog_array", "send_bin"))
	// // errs = append(errs, t.initTailCall(tailSendBinTP, "prog_array_tp", "send_bin_tp"))
	// for _, e := range errs {
	// 	if e != nil {
	// 		return e
	// 	}
	// }

	err := t.setStringFilter(t.config.Filter.CommFilter, "comm_filter", configCommFilter)
	if err != nil {
		return fmt.Errorf("error setting comm filter: %v", err)
	}

	eventsParams := t.initEventsParams()

	sysEnterTailsBPFMap, _ := t.bpfModule.GetMap("sys_enter_tails")

	paramsTypesBPFMap, _ := t.bpfModule.GetMap("params_types_map")
	paramsNamesBPFMap, _ := t.bpfModule.GetMap("params_names_map")
	for e := range t.eventsToTrace {
		params := eventsParams[e]
		var paramsTypes uint64
		var paramsNames uint64
		for n, param := range params {
			paramsTypes = paramsTypes | (uint64(param.encType) << (8 * n))
			paramsNames = paramsNames | (uint64(param.encName) << (8 * n))
		}
		paramsTypesBPFMap.Update(e, paramsTypes)
		paramsNamesBPFMap.Update(e, paramsNames)

		if e == ExecveEventID || e == ExecveatEventID {
			event, ok := EventsIDToEvent[e]
			if !ok {
				continue
			}

			probFnName := fmt.Sprintf("syscall__%s", event.Name)

			// execve functions require tail call on syscall enter as they perform extra work
			prog, err := t.bpfModule.GetProgram(probFnName)
			if err != nil {
				return fmt.Errorf("error loading BPF program %s: %v", probFnName, err)
			}
			sysEnterTailsBPFMap.Update(e, int32(prog.GetFd()))
			// log.Debug("execve:\t", prog.GetFd())
		}
	}
	t.containers.PopulateContainersBpfMap(t.bpfModule)

	return nil
}

// New creates a new Ctrace instance based on a given valid CtraceConfig
func New(cfg CtraceConfig) (*Ctrace, error) {
	var err error

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	// Tracee bpf code uses monotonic clock as event timestamp.
	// Get current monotonic clock so we can calculate event timestamps relative to it.
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) //从系统启动这一刻起开始计时,不受系统时间被用户改变的影响，即单调时间
	startTime := ts.Nano()                       //将单调时间转换为纳秒形式
	// Calculate the boot time using the monotonic time (since this is the clock we're using as a timestamp)
	// Note: this is NOT the real boot time, as the monotonic clock doesn't take into account system sleeps.
	bootTime := time.Now().UnixNano() - startTime

	t := &Ctrace{
		config:    cfg,
		startTime: uint64(startTime),
		bootTime:  uint64(bootTime),
	}
	t.SeccompSyscall = mapset.NewSet("")
	outf := os.Stdout

	log.Debug("New: events path: ", t.config.EventsPath)
	if t.config.EventsPath != "" {
		dir := filepath.Dir(t.config.EventsPath)
		os.MkdirAll(dir, 0755)
		os.Remove(t.config.EventsPath)
		outf, err = os.Create(t.config.EventsPath)
		if err != nil {
			return nil, err
		}
		log.Debug("New: set the outf by events path")
	}

	errf := os.Stderr
	log.Debug("New: errors path: ", t.config.ErrorsPath)
	if t.config.ErrorsPath != "" {
		dir := filepath.Dir(t.config.ErrorsPath)
		os.MkdirAll(dir, 0755)
		os.Remove(t.config.ErrorsPath)
		errf, err = os.Create(t.config.ErrorsPath)
		if err != nil {
			return nil, err
		}
		log.Debug("New: set the errf by events path")
	}

	log.Debug("New: set printer")
	t.printer, err = newEventPrinter(t.config.OutputFormat, cfg.RelativeTime, outf, errf)
	if err != nil {
		return nil, err
	}

	log.Debug("New: set containers")
	c := InitContainers()
	if err := c.Populate(); err != nil {
		return nil, fmt.Errorf("error initializing containers: %v", err)
	}
	t.containers = c

	log.Debug("New: set eventsToTrace")
	t.eventsToTrace = make(map[int32]bool, len(t.config.Filter.EventsToTrace))
	for _, e := range t.config.Filter.EventsToTrace {
		// Map value is true iff events requested by the user
		t.eventsToTrace[e] = true
	}

	// Compile final list of events to trace including essential events
	for id, event := range EventsIDToEvent {
		// If an essential event was not requested by the user, set its map value to false
		// 去掉未指定的事件
		if event.EssentialEvent && !t.eventsToTrace[id] {
			t.eventsToTrace[id] = false
		}
	}

	t.DecParamName[0] = make(map[argTag]ArgMeta)
	t.EncParamName[0] = make(map[string]argTag)
	t.DecParamName[1] = make(map[argTag]ArgMeta)
	t.EncParamName[1] = make(map[string]argTag)
	log.Debug("New: ready to init BPF")
	err = t.initBPF()
	if err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func (t *Ctrace) initBPF() error {
	var err error
	ebpfProgram, err := getEBPFProgramPath()
	if err != nil {
		return err
	}
	t.bpfModule, err = bpf.NewModuleFromFile(ebpfProgram)
	if err != nil {
		return fmt.Errorf("error creating bpf module from %s, %v", ebpfProgram, err)
	}
	supportRawTracepoints, err := supportRawTP()
	if err != nil {
		return fmt.Errorf("Failed to find kernel version: %v", err)
	}
	// BPFLoadObject() automatically loads ALL BPF programs according to their section type, unless set otherwise
	// For every BPF program, we need to make sure that:
	// 1. We disable autoload if the program is not required by any event and is not essential
	// 2. The correct BPF program type is set
	for _, event := range EventsIDToEvent {
		for _, probe := range event.Probes {
			prog, _ := t.bpfModule.GetProgram(probe.fn)
			if prog == nil && probe.attach == sysCall {
				prog, _ = t.bpfModule.GetProgram(fmt.Sprintf("syscall__%s", probe.fn))
			}
			if prog == nil {
				continue
			}
			if _, ok := t.eventsToTrace[event.ID]; !ok {
				// This event is not being traced - set its respective program(s) "autoload" to false
				err = prog.SetAutoload(false)
				if err != nil {
					return err
				}
				continue
			}
			// As kernels < 4.17 don't support raw tracepoints, set these program types to "regular" tracepoint
			if !supportRawTracepoints && (prog.GetType() == bpf.BPFProgTypeRawTracepoint) {
				err = prog.SetTracepoint()
				if err != nil {
					return err
				}
			}
		}
	}
	err = t.bpfModule.BPFLoadObject()
	if err != nil {
		return fmt.Errorf("error loading object from bpf module, %v", err)
	}

	err = t.populateBPFMaps()
	if err != nil {
		return fmt.Errorf("error populating ebpf map, %v", err)
	}

	log.Debug("initBPF: attaching BPF probs")
	log.Debug("len eventsToTrace:", len(t.eventsToTrace))

	for e, _ := range t.eventsToTrace {
		event, ok := EventsIDToEvent[e]
		if !ok {
			continue
		}
		// if !event.EssentialEvent {
		// 	log.Debug("event\t", event)
		// }
		for _, probe := range event.Probes {
			if probe.attach == sysCall {
				// Already handled by raw_syscalls tracepoints
				continue
			}
			prog, err := t.bpfModule.GetProgram(probe.fn)
			if err != nil {
				return fmt.Errorf("error getting program %s: %v", probe.fn, err)
			}
			// if !event.EssentialEvent {
			log.Debug("got program\t", probe.fn)
			// }
			if probe.attach == rawTracepoint && !supportRawTracepoints {
				// We fallback to regular tracepoint in case kernel doesn't support raw tracepoints (< 4.17)
				probe.attach = tracepoint
				log.Debug("set" + probe.fn + "probe.attach from rawTracepoint to tracepoint")
			}
			switch probe.attach {
			case kprobe:
				_, err = prog.AttachKprobe(probe.event)
			case kretprobe:
				_, err = prog.AttachKretprobe(probe.event)
			case tracepoint:
				_, err = prog.AttachTracepoint(probe.event)
			case rawTracepoint:
				tpEvent := strings.Split(probe.event, ":")[1]
				_, err = prog.AttachRawTracepoint(tpEvent)
			}
			if err != nil {
				return fmt.Errorf("error attaching event %s: %v", probe.event, err)
			}
			if !event.EssentialEvent {
				log.Debug("attached not EssentialEvent program\t", probe.event, probe.fn, probe.attach)
			}
		}
	}

	log.Debug("initBPF: set events perf buf")
	t.eventsChannel = make(chan []byte, 5000)
	t.lostEvChannel = make(chan uint64)
	t.eventsPerfMap, err = t.bpfModule.InitPerfBuf("events", t.eventsChannel, t.lostEvChannel, t.config.PerfBufferSize)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	// t.fileWrChannel = make(chan []byte, 1000)
	// t.lostWrChannel = make(chan uint64)
	// t.fileWrPerfMap, err = t.bpfModule.InitPerfBuf("file_writes", t.fileWrChannel, t.lostWrChannel, t.config.BlobPerfBufferSize)
	// if err != nil {
	// 	return fmt.Errorf("error initializing file_writes perf map: %v", err)
	// }

	return nil
}

// Initialize tail calls program array
func (t *Ctrace) initTailCall(tailNum uint32, mapName string, progName string) error {

	bpfMap, err := t.bpfModule.GetMap(mapName)
	if err != nil {
		return err
	}
	bpfProg, err := t.bpfModule.GetProgram(progName)
	if err != nil {
		return fmt.Errorf("could not get BPF program "+progName+": %v", err)
	}
	fd := bpfProg.GetFd()
	if fd < 0 {
		return fmt.Errorf("could not get BPF program FD for "+progName+": %v", err)
	}
	err = bpfMap.Update(unsafe.Pointer(&tailNum), unsafe.Pointer(&fd))

	return err
}

// Run starts the trace. it will run until interrupted
func (t *Ctrace) Run() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	// 定时退出
	if t.config.TraceTime > 0 {
		fmt.Println("Stop tracking after", t.config.TraceTime, "seconds.")
		time.AfterFunc(time.Duration(t.config.TraceTime)*time.Second, func() {
			t.eventsPerfMap.Stop()
			t.printer.Epilogue(t.stats)
			close(done)
			t.Close()
			cmd := exec.Command("/bin/sh", "-c", "...........")
			// Go会将PGID设置成与PID相同的值
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		})
	}
	log.Debug("Run: start to print info")
	t.printer.Preamble()
	t.eventsPerfMap.Start()
	go t.processLostEvents()
	go t.processEvents(done)
	<-sig
	t.eventsPerfMap.Stop()
	t.printer.Epilogue(t.stats)
	close(done)
	t.Close()
	log.Debug("Run: ctrace closed")
	return nil
}

// write the seccomp profile to the profilePath file given an architecture and a list of syscalls (name)
func (t *Ctrace) writeSeccompProfile(arch specs.Arch, profilePath string) {
	// set to string
	syscallSet := t.SeccompSyscall.ToSlice()
	syscallSlice := make([]string, len(syscallSet))
	for i, arg := range syscallSet {
		syscallSlice[i] = arg.(string)
	}
	sort.Strings(syscallSlice)
	// trim
	if syscallSlice[0] == "" {
		syscallSlice = syscallSlice[1:]
	}

	// add missing syscall
	// missingSyscall := []string{"exit_group", "rt_sigreturn"}
	missingSyscall := []string{"futex", "exit_group", "fchdir", "mount", "pivot_root", "rt_sigreturn", "sethostname", "umask", "umount2", "pselect6", "tgkill"}
	for _, v := range missingSyscall {
		index := sort.SearchStrings(syscallSlice, v)
		if index < len(syscallSlice) && syscallSlice[index] == v { //需要注意此处的判断，先判断 &&左侧的条件，如果不满足则结束此处判断，不会再进行右侧的判断
			continue
		} else {
			syscallSlice = append(syscallSlice, v)
		}
	}

	// syscallSlice = append(syscallSlice, missingSyscall...)

	fmt.Printf("\n%d syscalls were traced\n", len(syscallSlice))
	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{arch},
		Syscalls: []specs.LinuxSyscall{
			specs.LinuxSyscall{
				Names:  syscallSlice,
				Action: specs.ActAllow,
			},
		},
	}

	profileFile, err := os.Create(profilePath)
	if err != nil {
		log.Fatalf("Failed to create seccomp profile: %v", err)
	}
	defer profileFile.Close()

	enc := json.NewEncoder(profileFile)
	enc.SetIndent("", "    ")
	enc.Encode(profile)
	fmt.Printf("Saved seccomp profile at %v\n", profilePath)
}

// Close cleans up created resources
func (t Ctrace) Close() {
	if t.config.Seccomp {
		t.writeSeccompProfile("SCMP_ARCH_X86_64", "./seccomp.json")
	}

	if t.bpfModule != nil {
		t.bpfModule.Close()
	}
	t.printer.Close()
}

func (t *Ctrace) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		t.stats.lostEvCounter.Increment(int(lost))
	}
}

func (t *Ctrace) handleError(err error) {
	t.stats.errorCounter.Increment()
	t.printer.Error(err)
}

type RawEvent struct {
	Ctx      context
	RawArgs  map[argTag]interface{}
	ArgsTags []argTag
}

func (t *Ctrace) processEvents(done <-chan struct{}) error {
	//list of <-chan error
	//<-chan error: use this to send struct error data
	var errcList []<-chan error

	// Source pipeline stage.
	rawEventChan, errc, err := t.decodeRawEvent(done)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	processedEventChan, errc, err := t.processRawEvent(done, rawEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	printEventChan, errc, err := t.prepareEventForPrint(done, processedEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)
	errc, err = t.printEvent(done, printEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	// Pipeline started. Waiting for pipeline to complete
	return t.WaitForPipeline(errcList...)
}

func (t *Ctrace) decodeRawEvent(done <-chan struct{}) (<-chan RawEvent, <-chan error, error) {
	out := make(chan RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range t.eventsChannel {
			dataBuff := bytes.NewBuffer(dataRaw)
			var ctx context
			err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
			if err != nil {
				errc <- err
				continue
			}
			rawArgs := make(map[argTag]interface{})
			argsTags := make([]argTag, ctx.Argc)
			for i := 0; i < int(ctx.Argc); i++ {
				tag, val, err := readArgFromBuff(dataBuff)
				if err != nil {
					errc <- err
					continue
				}
				argsTags[i] = tag
				rawArgs[tag] = val

				// fmt.Printf("tag:%s,val:%s\t", tag, val)
				// fmt.Println()
			}
			select {
			case out <- RawEvent{ctx, rawArgs, argsTags}:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

func (t *Ctrace) processRawEvent(done <-chan struct{}, in <-chan RawEvent) (<-chan RawEvent, <-chan error, error) {
	out := make(chan RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for rawEvent := range in {
			err := t.processEvent(&rawEvent.Ctx, rawEvent.RawArgs)
			if err != nil {
				errc <- err
				continue
			}
			select {
			case out <- rawEvent:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

func (t *Ctrace) processEvent(ctx *context, args map[argTag]interface{}) error {
	return nil
}

func (t *Ctrace) prepareEventForPrint(done <-chan struct{}, in <-chan RawEvent) (<-chan Event, <-chan error, error) {
	out := make(chan Event, 5000)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for rawEvent := range in {
			err := t.prepareArgsForPrint(&rawEvent.Ctx, rawEvent.RawArgs)
			if err != nil {
				errc <- err
				continue
			}
			args := make([]interface{}, rawEvent.Ctx.Argc)
			argMetas := make([]ArgMeta, rawEvent.Ctx.Argc)
			for i, tag := range rawEvent.ArgsTags {
				args[i] = rawEvent.RawArgs[tag]
				argMeta, ok := t.DecParamName[rawEvent.Ctx.Event_id%2][tag]
				if ok {
					argMetas[i] = argMeta
				} else {
					errc <- fmt.Errorf("Invalid arg tag for event %d", rawEvent.Ctx.Event_id)
					continue
				}

			}
			// Currently, the timestamp received from the bpf code is of the monotonic clock.
			// Todo: The monotonic clock doesn't take into account system sleep time.
			// Starting from kernel 5.7, we can get the timestamp relative to the system boot time instead which is preferable.
			if t.config.RelativeTime {
				// To get the monotonic time since tracee was started, we have to substract the start time from the timestamp.
				rawEvent.Ctx.Ts -= t.startTime
			} else {
				// To get the current ("wall") time, we add the boot time into it.
				rawEvent.Ctx.Ts += t.bootTime
			}
			// fmt.Println(argMetas, "\t", args)
			evt, err := newEvent(rawEvent.Ctx, argMetas, args)
			if err != nil {
				errc <- err
				continue
			}
			select {
			case out <- evt:
			case <-done:
				return
			}
		}
	}()
	return out, errc, nil
}

func (t *Ctrace) printEvent(done <-chan struct{}, in <-chan Event) (<-chan error, error) {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for printEvent := range in {
			t.stats.eventCounter.Increment()
			t.printer.Print(printEvent)
			if t.config.Seccomp {
				t.SeccompSyscall.Add(printEvent.EventName)
			}
		}
	}()
	return errc, nil
}

func (t *Ctrace) WaitForPipeline(errs ...<-chan error) error {
	errc := MergeErrors(errs...)
	for err := range errc {
		t.handleError(err)
	}
	return nil
}

// MergeErrors merges multiple channels of errors.
// Based on https://blog.golang.org/pipelines.
func MergeErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	// We must ensure that the output channel has the capacity to hold as many errors
	// as there are error channels. This will ensure that it never blocks, even
	// if WaitForPipeline returns early.
	out := make(chan error, len(cs))

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (t *Ctrace) prepareArgsForPrint(ctx *context, args map[argTag]interface{}) error {
	for key, arg := range args {
		if ptr, isUintptr := arg.(uintptr); isUintptr {
			args[key] = fmt.Sprintf("0x%X", ptr)
			// fmt.Println("%s", args[key])
		}
	}
	switch ctx.Event_id {
	case SysEnterEventID, SysExitEventID, CapCapableEventID:
		//show syscall name instead of id
		if id, isInt32 := args[t.EncParamName[ctx.Event_id%2]["syscall"]].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				if event.Probes[0].attach == sysCall {
					args[t.EncParamName[ctx.Event_id%2]["syscall"]] = event.Probes[0].event
				}
			}
		}
		if ctx.Event_id == CapCapableEventID {
			if cap, isInt32 := args[t.EncParamName[ctx.Event_id%2]["cap"]].(int32); isInt32 {
				args[t.EncParamName[ctx.Event_id%2]["cap"]] = PrintCapability(cap)
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if prot, isInt32 := args[t.EncParamName[ctx.Event_id%2]["prot"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["prot"]] = PrintMemProt(uint32(prot))
		}
	case PtraceEventID:
		if req, isInt64 := args[t.EncParamName[ctx.Event_id%2]["request"]].(int64); isInt64 {
			args[t.EncParamName[ctx.Event_id%2]["request"]] = PrintPtraceRequest(req)
		}
	case PrctlEventID:
		if opt, isInt32 := args[t.EncParamName[ctx.Event_id%2]["option"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["option"]] = PrintPrctlOption(opt)
		}
	case SocketEventID:
		if dom, isInt32 := args[t.EncParamName[ctx.Event_id%2]["domain"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["domain"]] = PrintSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args[t.EncParamName[ctx.Event_id%2]["type"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["type"]] = PrintSocketType(uint32(typ))
		}
	case ConnectEventID, AcceptEventID, Accept4EventID, BindEventID, GetsocknameEventID:
		if sockAddr, isStrMap := args[t.EncParamName[ctx.Event_id%2]["addr"]].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[t.EncParamName[ctx.Event_id%2]["addr"]] = s
		}
	case AccessEventID, FaccessatEventID:
		if mode, isInt32 := args[t.EncParamName[ctx.Event_id%2]["mode"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["mode"]] = PrintAccessMode(uint32(mode))
		}
	case ExecveatEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.Event_id%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["flags"]] = PrintExecFlags(uint32(flags))
		}
	case OpenEventID, OpenatEventID, SecurityFileOpenEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.Event_id%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["flags"]] = PrintOpenFlags(uint32(flags))
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if mode, isUint32 := args[t.EncParamName[ctx.Event_id%2]["mode"]].(uint32); isUint32 {
			args[t.EncParamName[ctx.Event_id%2]["mode"]] = PrintInodeMode(mode)
		}
	case MemProtAlertEventID:
		if alert, isAlert := args[t.EncParamName[ctx.Event_id%2]["alert"]].(alert); isAlert {
			args[t.EncParamName[ctx.Event_id%2]["alert"]] = PrintAlert(alert)
		}
	case CloneEventID:
		if flags, isUint64 := args[t.EncParamName[ctx.Event_id%2]["flags"]].(uint64); isUint64 {
			args[t.EncParamName[ctx.Event_id%2]["flags"]] = PrintCloneFlags(flags)
		}
	case SendtoEventID, RecvfromEventID:
		addrTag := t.EncParamName[ctx.Event_id%2]["dest_addr"]
		if ctx.Event_id == RecvfromEventID {
			addrTag = t.EncParamName[ctx.Event_id%2]["src_addr"]
		}
		if sockAddr, isStrMap := args[addrTag].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[addrTag] = s
		}
	case BpfEventID:
		if cmd, isInt32 := args[t.EncParamName[ctx.Event_id%2]["cmd"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["cmd"]] = PrintBPFCmd(cmd)
		}
	}

	return nil
}

func boolToUInt32(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return uint32(0)
}

func copyFileByPath(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	return nil
}

type alert struct {
	Ts      uint64
	Msg     uint32
	Payload uint8
}

func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	var size uint32
	err = binary.Read(buff, binary.LittleEndian, &size)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	if size > 4096 {
		return "", fmt.Errorf("string size too big: %d", size)
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) //last byte is string terminating null
	defer func() {
		var dummy int8
		binary.Read(buff, binary.LittleEndian, &dummy) //discard last byte which is string terminating null
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string arg: %v", err)
	}
	return string(res), nil
}

// readStringVarFromBuff reads a null-terminated string from `buff`
func readStringVarFromBuff(buff io.Reader, max int) (string, error) {
	var err error
	var char int8
	res := make([]byte, max)
	err = binary.Read(buff, binary.LittleEndian, &char)
	if err != nil {
		return "", fmt.Errorf("error reading null terminated string: %v", err)
	}
	for count := 1; char != 0 && count < max; count++ {
		res = append(res, byte(char))
		err = binary.Read(buff, binary.LittleEndian, &char)
		if err != nil {
			return "", fmt.Errorf("error reading null terminated string: %v", err)
		}
	}
	res = bytes.TrimLeft(res[:], "\000")
	return string(res), nil
}

func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = binary.Read(buff, binary.LittleEndian, &res)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

func readSockaddrFromBuff(buff io.Reader) (map[string]string, error) {
	res := make(map[string]string, 3)
	var family int16
	err := binary.Read(buff, binary.LittleEndian, &family)
	if err != nil {
		return nil, err
	}
	res["sa_family"] = PrintSocketDomain(uint32(family))
	switch family {
	case 1: // AF_UNIX
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		var sunPathBuf [108]byte
		err := binary.Read(buff, binary.LittleEndian, &sunPathBuf)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}
		trimmedPath := bytes.TrimLeft(sunPathBuf[:], "\000")
		sunPath := ""
		if len(trimmedPath) != 0 {
			sunPath, err = readStringVarFromBuff(bytes.NewBuffer(trimmedPath), 108)
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}
		res["sun_path"] = sunPath
	case 2: // AF_INET
		/*
			http://man7.org/linux/man-pages/man7/ip.7.html
			struct sockaddr_in {
				sa_family_t    sin_family; // address family: AF_INET
				in_port_t      sin_port;   // port in network byte order
				struct in_addr sin_addr;   // internet address
				// byte        padding[8]; //https://elixir.bootlin.com/linux/v4.20.17/source/include/uapi/linux/in.h#L232
			};
			struct in_addr {
				uint32_t       s_addr;     // address in network byte order
			};
		*/
		var port uint16
		err = binary.Read(buff, binary.BigEndian, &port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_port"] = strconv.Itoa(int(port))
		var addr uint32
		err = binary.Read(buff, binary.BigEndian, &addr)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_addr"] = PrintUint32IP(addr)
		_, err := readByteSliceFromBuff(buff, 8)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
	case 10: // AF_INET6
		/*
			struct sockaddr_in6 {
				sa_family_t     sin6_family;   // AF_INET6
				in_port_t       sin6_port;     // port number
				uint32_t        sin6_flowinfo; // IPv6 flow information
				struct in6_addr sin6_addr;     // IPv6 address
				uint32_t        sin6_scope_id; // Scope ID (new in 2.4)
			};

			struct in6_addr {
				unsigned char   s6_addr[16];   // IPv6 address
			};
		*/
		var port uint16
		err = binary.Read(buff, binary.BigEndian, &port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_port"] = strconv.Itoa(int(port))

		var flowinfo uint32
		err = binary.Read(buff, binary.BigEndian, &flowinfo)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_flowinfo"] = strconv.Itoa(int(flowinfo))
		addr, err := readByteSliceFromBuff(buff, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_addr"] = Print16BytesSliceIP(addr)
		var scopeid uint32
		err = binary.Read(buff, binary.BigEndian, &scopeid)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_scopeid"] = strconv.Itoa(int(scopeid))
	}
	return res, nil
}

func readArgFromBuff(dataBuff io.Reader) (argTag, interface{}, error) {
	var err error
	var res interface{}
	var argTag argTag
	var argType argType
	err = binary.Read(dataBuff, binary.LittleEndian, &argType)
	if err != nil {
		return argTag, nil, fmt.Errorf("error reading arg type: %v", err)
	}
	err = binary.Read(dataBuff, binary.LittleEndian, &argTag)
	if err != nil {
		return argTag, nil, fmt.Errorf("error reading arg tag: %v", err)
	}
	switch argType {
	case intT:
		var data int32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case uintT, devT, modeT:
		var data uint32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case longT:
		var data int64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case ulongT, offT, sizeT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case pointerT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = uintptr(data)
	case sockAddrT:
		res, err = readSockaddrFromBuff(dataBuff)
	case alertT:
		var data alert
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case strT:
		res, err = readStringFromBuff(dataBuff)
	case strArrT:
		var ss []string
		var arrLen uint8
		err = binary.Read(dataBuff, binary.LittleEndian, &arrLen)
		if err != nil {
			return argTag, nil, fmt.Errorf("error reading string array number of elements: %v", err)
		}
		for i := 0; i < int(arrLen); i++ {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return argTag, nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)
		}
		res = ss
	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return argTag, nil, fmt.Errorf("error unknown arg type %v", argType)
	}
	if err != nil {
		return argTag, nil, err
	}
	return argTag, res, nil
}
