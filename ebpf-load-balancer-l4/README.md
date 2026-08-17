# Simple IPv4 eBPF Load Balancer L4


## Quickstart

```shell
go mod tidy
go generate ./...
GOOS=linux GOARCH=amd64 go build -o ebpf-load-balancer-l4
sudo ./ebpf-load-balancer-l4
```

## NOTICE

This tool uses includes from the common directory which is in the root of this repository.
You can change it to your own path or replace them.
