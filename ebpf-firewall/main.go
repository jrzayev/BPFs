//
// Created by Javid Rzayev on 17.08.26.
//

package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"gopkg.in/yaml.v3"
)

type interfaceInfo struct {
	InterfaceName string `yaml:"interfaceName"`
}

type ipv4BlackListInfo struct {
	IPv4BlackList []string `yaml:"ipv4BlackList"`
}

type ipv6BlackListInfo struct {
	IPv6BlackList []string `yaml:"ipv6BlackList"`
}

func main() {
	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	defer objs.Close()
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Can't read config file: ", err)
	}

	var config interfaceInfo
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal("Can't parse config file: ", err)
	}

	log.Println("eBPF objects loaded into memory successfully!")

	iface, err := net.InterfaceByName(config.InterfaceName)
	if err != nil {
		log.Fatal("Can't find interface: ", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewall,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatal("Can't attach XDP: ", err)
	}
	defer l.Close()
	addIPv4(objs, data)
	addIPv6(objs, data)
	log.Println("XDP attached successfully!")
	log.Println("Press Ctrl+C to exit")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("Shutting down...")
}

func addIPv4(objs firewallObjects, data []byte) {
	var config ipv4BlackListInfo
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal("Can't parse config file: ", err)
	}
	var value uint32 = 1
	for _, ip := range config.IPv4BlackList {
		ipv4 := net.ParseIP(ip).To4()
		if ipv4 == nil {
			log.Fatalf("Invalid IPv4 address: %s", ip)
		}
		err := objs.Ipv4BlackList.Put(ipv4, value)
		if err != nil {
			log.Fatal("Can't add IPv4 to the map: ", err)
		}
	}
}

func addIPv6(objs firewallObjects, data []byte) {
	var config ipv6BlackListInfo
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal("Can't parse config file: ", err)
	}
	var value uint32 = 1
	for _, ip := range config.IPv6BlackList {
		ipv6 := net.ParseIP(ip).To16()
		if ipv6 == nil {
			log.Fatalf("Invalid IPv6 address: %s", ip)
		}
		err := objs.Ipv6BlackList.Put(ipv6, value)
		if err != nil {
			log.Fatal("Can't add IPv6 to the map: ", err)
		}
	}
}
