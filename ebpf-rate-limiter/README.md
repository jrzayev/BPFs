# Simple eBPF Rate Limiter


## Quickstart

```shell
go mod tidy
go generate ./...
GOOS=linux GOARCH=amd64 go build -o ebpf-rate-limiter
sudo ./ebpf-rate-limiter
```

## NOTICE

This tool uses includes from the common directory which is in the root of this repository.
You can change it to your own path or replace them.
