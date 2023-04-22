package main

import (
	"encoding/json"
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

	localIP, localIF, localIName := probes.GetLocalIP()
	log.Printf("local ip: %s on %d of %s\n", localIP, localIF, localIName)

	uname, _ := probes.GetOSUnamer()
	unameBytes, _ := json.MarshalIndent(uname, "", "\t")
	log.Println(string(unameBytes))

	log.Println("jebpf start...")
	log.Printf("process pid: %d\n", os.Getpid())

	probes.RunProbes()

	<-stopper

	probes.StopProbes()

	log.Println("Received signal, exiting program..")

}
