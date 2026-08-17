# Simple eBPF firewall


## Quickstart

```shell
go mod tidy
go generate ./...
GOOS=linux GOARCH=amd64 go build -o ebpf-firewall
sudo ./ebpf-firewall
```

## NOTICE

This tool uses includes from the common directory which is in the root of this repository.
You can change it to your own path or replace them.
