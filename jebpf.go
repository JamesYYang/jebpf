package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/JamesYYang/jebpf/probes"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	log.Println("jebpf start...")
	log.Printf("process pid: %d\n", os.Getpid())

	probes.RunProbes()

	<-stopper

	probes.StopProbes()

	log.Println("Received signal, exiting program..")

}
