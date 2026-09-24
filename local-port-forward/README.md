# Simple Local eBPF Port Forward


## Quickstart

```shell
go mod tidy
go generate ./...
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o local-port-forward
sudo ./local-port-forward
```

## NOTICE

This tool uses includes from the common directory which is in the root of this repository.
You can change it to your own path or replace them.
