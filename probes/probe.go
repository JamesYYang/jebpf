package probes

import (
	"log"
)

type IProbe interface {
	Name() string
	Start()
	Stop()
}

var probes = make(map[string]IProbe)

func RegisterProbe(p IProbe) {
	name := p.Name()
	if _, ok := probes[name]; !ok {
		log.Printf("Register probe: %s", name)
		probes[name] = p
	}
}

func RunProbes() {
	for _, p := range probes {
		log.Printf("start to run %s probe", p.Name())
		p.Start()
	}
}

func StopProbes() {
	for _, p := range probes {
		log.Printf("stop %s probe", p.Name())
		p.Stop()
	}
}
