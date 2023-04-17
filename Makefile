CLANG ?= clang-10
CFLAGS := '-O2 -g -Wall -Werror $(CFLAGS)'
TARGETS ?= bpfel,bpfeb
HEADERS ?= ./ebpf/headers

all: probe-hello probe-openat build

probe-hello: export GOPACKAGE=hello
probe-hello:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem hello bpf ./ebpf/hello.bpf.c -- -I $(HEADERS) 
	mv hello_*.* ./probes/hello

probe-openat: export GOPACKAGE=openat
probe-openat:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem openat -type sys_openat_event bpf ./ebpf/tp_openat.bpf.c -- -I $(HEADERS) 
	mv openat_*.* ./probes/openat

probe-tcpstate: export GOPACKAGE=tcpstate
probe-tcpstate:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem tcpstate -type net_tcp_event bpf ./ebpf/tcp_connect.bpf.c -- -I $(HEADERS) 
	mv tcpstate_*.* ./probes/tcpstate

build:
	go build -o jebpf

run:
	./jebpf