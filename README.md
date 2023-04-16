# jebpf
research on ebpf-go

## how to run

install bpf2go

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

re-generate go file

```bash
make 

```

run program
```bash
sudo make run
```