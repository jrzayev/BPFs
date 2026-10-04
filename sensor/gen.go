//
// Crated by Javid Rzayev 10/1/2026
//

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type parm -type info -target amd64,arm64 bpf sensor.c -- -I ../common -mcpu=v3
