//
// Created by Javid Rzayev on 18.08.26.
//

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

const maxBackends = 1024

type loadBalancer struct {
	Vip      string   `yaml:"vip"`
	Port     uint16   `yaml:"port"`
	Backends []string `yaml:"backends"`
}

type appConfig struct {
	InterfaceName string         `yaml:"interfaceName"`
	LoadBalancers []loadBalancer `yaml:"loadBalancers"`
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock: ", err)
	}

	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Reading config file: ", err)
	}
	var config appConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal("Parsing config file: ", err)
	}

	iface, err := net.InterfaceByName(config.InterfaceName)
	if err != nil {
		log.Fatal("Can't find interface: ", err)
	}

	var objs load_balancerObjects
	if err := loadLoad_balancerObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	defer objs.Close()
	log.Println("eBPF objects loaded into memory successfully!")

	if err := setConfig(&objs, config.LoadBalancers); err != nil {
		log.Fatal("Applying config: ", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalance,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Can't attach XDP: ", err)
	}
	defer l.Close()
	log.Printf("XDP attached to %s successfully!", config.InterfaceName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	log.Println("Press Ctrl+C to exit")
	<-sig
	log.Println("Detaching XDP and exiting")
}

func setConfig(objs *load_balancerObjects, lbs []loadBalancer) error {
	if len(lbs) == 0 {
		return fmt.Errorf("no loadBalancers defined")
	}

	base := uint32(0)
	for _, lb := range lbs {
		vip, err := ipToNetU32(lb.Vip)
		if err != nil {
			return fmt.Errorf("vip %q: %w", lb.Vip, err)
		}
		if lb.Port == 0 {
			return fmt.Errorf("vip %q: port is required", lb.Vip)
		}
		if len(lb.Backends) == 0 {
			return fmt.Errorf("vip %q: no backends", lb.Vip)
		}
		if base+uint32(len(lb.Backends)) > maxBackends {
			return fmt.Errorf("too many backends, limit is %d", maxBackends)
		}

		for i, be := range lb.Backends {
			ip, err := ipToNetU32(be)
			if err != nil {
				return fmt.Errorf("backend %q: %w", be, err)
			}
			if err := objs.Backends.Put(base+uint32(i), load_balancerBackend{Ip: ip}); err != nil {
				return fmt.Errorf("can't add backend %q to the map: %w", be, err)
			}
		}

		val := load_balancerConfig{
			Vip:   vip,
			Base:  base,
			Count: uint32(len(lb.Backends)),
			Port:  portToNetU16(lb.Port),
		}
		if err := objs.Configs.Put(vip, val); err != nil {
			return fmt.Errorf("can't add vip %q to the map: %w", lb.Vip, err)
		}
		log.Printf("%s:%d -> %v", lb.Vip, lb.Port, lb.Backends)

		base += uint32(len(lb.Backends))
	}
	return nil
}

func ipToNetU32(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address")
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}
	return binary.NativeEndian.Uint32(v4), nil
}

func portToNetU16(port uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], port)
	return binary.NativeEndian.Uint16(b[:])
}
