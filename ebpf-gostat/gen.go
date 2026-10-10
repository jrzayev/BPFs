//
// Crated by Javid Rzayev 10/5/2026
//

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type goid_off_val -type goid_summary -type goid_cur -target amd64,arm64 bpf ebpf-gostat.c -- -I ../common
