# ctrace
## how to build ctrace
`$make build`
you can use blow cmd to clean
`$make clean`
more details see Makefile

## how to run ctrace
1. build ctrace first
2. `sudo ./dist/ctrace` to run the CLI
3. the HELP INFO shows the intructions

## design overview
1. ctrace entrance: main.go
2. main.go calls cli.App to run the command line applicaion
3. all commands are define under /ctrace/command
4. the /ctrace/command/common.go defines the global flags/action
5. /ctrace/bpf contains the ebpf files
6. ctrace.go defines the userspace functions
