SRC = $(shell find . -type f -name '*.go' ! -name '*_test.go' )
BPFFILE = ctrace/bpf
OUTPUT = dist
BPFOUTPUT = dist/ctrace.bpf.o

VMLINUXH = ${BPFFILE}/vmlinux.h
BTFFILE = /sys/kernel/btf/vmlinux
BPFTOOL = $(shell which bpftool || /bin/false)
DBGVMLINUX = /usr/lib/debug/boot/vmlinux-$(shell uname -r)

CGO_CFLAGS="-I /usr/include/bpf"
CGO_LDFLAGS="-lelf -lz -lbpf"
CFLAGS =-g -O2 -c -Wall -fpie -Wno-unused-variable -Wno-unused-function

.PHONY: build
build: ${BPFOUTPUT} ctrace 

$(OUTPUT):
	mkdir -p $(OUTPUT)

#vmlinux header file
.PHONY: vmlinuxh
vmlinuxh: $(VMLINUXH)

$(VMLINUXH): $(OUTPUT)
ifeq ($(wildcard $(BPFTOOL)),)
	@echo "ERROR: could not find bpftool, install linux-tools-common and try again"
	@exit 1
endif
	@if [ -f $(DBGVMLINUX) ]; then \
		echo "INFO: found dbg kernel, generating $(VMLINUXH) from $(DBGVMLINUX)"; \
		$(BPFTOOL) btf dump file $(DBGVMLINUX) format c > $(VMLINUXH); \
	fi
	@if [ ! -f $(BTFFILE) ] && [ ! -f $(DBGVMLINUX) ]; then \
		echo "ERROR: kernel does not seem to support BTF"; \
		exit 1; \
	fi
	@if [ ! -f $(VMLINUXH) ]; then \
		echo "INFO: generating $(VMLINUXH) from $(BTFFILE)"; \
		$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUXH); \
	fi

#ctrace.bpf.o
.PHONY: bpf-x86
${BPFOUTPUT}: ${BPFFILE}/ctrace.bpf.c | vmlinuxh
	clang $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 \
	${BPFFILE}/ctrace.bpf.c -o ${BPFOUTPUT}
	
.PHONY: bpf-arm64
bpf-arm64: ${BPFFILE}/ctrace.bpf.c | vmlinuxh
	clang $(CFLAGS) -target bpf -D__TARGET_ARCH_arm64 \
	-o ${OUTPUT}/ctrace.bpf.o ${BPFFILE}/ctrace.bpf.c

#ctrace
.PHONY: ctrace
ctrace: $(SRC)
	GOOS=linux cc=gcc CGO_CFLAGS=$(CGO_CFLAGS) CGO_LDFLAGS=$(CGO_LDFLAGS) \
	go build -v -o ${OUTPUT}/ctrace


#clean
.PHONY: clean
clean:
	rm -rf ${OUTPUT}