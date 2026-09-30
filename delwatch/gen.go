//
// Crated by Javid Rzayev 9/30/2026
//

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type parm -target amd64,arm64 bpf delwatch.c -- -I ../common 
