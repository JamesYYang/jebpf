CLANG ?= clang-12
CFLAGS := '-O2 -g -Wall -Werror $(CFLAGS)'
TARGETS ?= bpf
HEADERS ?= ./ebpf/headers

all: probe-hello probe-openat probe-tcpstate probe-tcpretrans probe-tccapture build

probe-hello: export GOPACKAGE=hello
probe-hello:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem hello kpHello ./ebpf/hello.bpf.c -- -I $(HEADERS) 
	mv hello_*.* ./probes/hello

probe-openat: export GOPACKAGE=openat
probe-openat:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem openat -type sys_openat_event bpf ./ebpf/tp_openat.bpf.c -- -I $(HEADERS) 
	mv openat_*.* ./probes/openat

probe-tcpstate: export GOPACKAGE=tcpstate
probe-tcpstate:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem tcpstate -type net_tcp_event bpf ./ebpf/tcp_connect.bpf.c -- -I $(HEADERS) 
	mv tcpstate_*.* ./probes/tcpstate

probe-tcpretrans: export GOPACKAGE=tcpretrans
probe-tcpretrans:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem tcpretrans -type net_tcp_event bpf ./ebpf/tcp_retrans.bpf.c -- -I $(HEADERS) 
	mv tcpretrans_*.* ./probes/tcpretrans

probe-tcpreset: export GOPACKAGE=tcpreset
probe-tcpreset:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem tcpreset -type net_tcp_event bpf ./ebpf/tcp_reset.bpf.c -- -I $(HEADERS) 
	mv tcpreset_*.* ./probes/tcpreset

probe-tccapture: export GOPACKAGE=tccapture
probe-tccapture:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -output-stem tccapture -type net_packet_event tccapture ./ebpf/tc_capture.bpf.c -- -I $(HEADERS) 
	mv tccapture_*.* ./probes/tccapture

build:
	go build -o jebpf

run:
	./jebpf