//
// Created by jr-free on 10/1/26.
//

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type info -target amd64,arm64 bpf tcledger.c -- -I../common
