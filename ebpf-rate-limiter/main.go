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

type RateLimit struct {
	IP    string `yaml:"ip"`
	Limit uint32 `yaml:"limit"`
}

type rateLimiterInfo struct {
	RateLimits []RateLimit `yaml:"rateLimits"`
}

func main() {
	var objs rate_limiterObjects
	if err := loadRate_limiterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	log.Println("eBPF objects loaded into memory successfully!")

	defer objs.Close()
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Reading config file: ", err)
	}
	var config interfaceInfo
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal("Parsing config file: ", err)
	}

	iface, err := net.InterfaceByName(config.InterfaceName)
	if err != nil {
		log.Fatal("Can't find interface: ", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRateLimit,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatal("Can't attach XDP: ", err)
	}
	defer l.Close()
	log.Println("XDP attached successfully!")

	setCustomLimit(objs, data)
	log.Println("Press Ctrl+C to exit")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("Shutting down...")
}

func setCustomLimit(objs rate_limiterObjects, data []byte) {
	var config rateLimiterInfo
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal("Parsing config file: ", err)
	}
	for _, rl := range config.RateLimits {
		ip := net.ParseIP(rl.IP).To4()
		if ip == nil {
			log.Fatalf("Invalid IP address: %s", rl.IP)
		}

		limit := uint32(rl.Limit)
		err := objs.RateLimit.Put(ip, limit)
		if err != nil {
			log.Fatal("Can't add IP to the map: ", err)
		}
		log.Printf("IP %s set to %d requests per second\n", ip.String(), rl.Limit)
	}
}
