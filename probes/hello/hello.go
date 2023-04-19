package hello

import (
	"log"

	"github.com/JamesYYang/jebpf/probes"
	"github.com/cilium/ebpf/link"
)

type Hello_Probe struct {
	name string
	bpf  *kpHelloObjects
	link link.Link
}

func init() {
	h := &Hello_Probe{}
	h.name = "hello_bpf"
	probes.RegisterProbe(h)
}

func (p *Hello_Probe) Name() string {
	return p.name
}

func (p *Hello_Probe) Start() {

	objs := kpHelloObjects{}
	if err := loadKpHelloObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	p.bpf = &objs

	kp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleTp, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	p.link = kp

}

func (p *Hello_Probe) Stop() {
	p.bpf.Close()
	p.link.Close()
}
