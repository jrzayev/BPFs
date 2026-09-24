//
// Created by Javid Rzayev on 9/24/26.
//

package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

type portMap struct {
	SrcPort uint32 `yaml:"srcPort"`
	DstPort uint32 `yaml:"dstPort"`
}

type appConfig struct {
	PortMaps []portMap `yaml:"portMaps"`
}

func main() {
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal("Removing memlock:", err)
	}
	var objs port_forwardObjects
	if err := loadPort_forwardObjects(&objs, nil); err != nil {
		log.Fatal("Loading BPF objects: ", err)
	}
	defer objs.Close()

	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Read config file failed: ", err)
	}

	var config appConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatal("Unmarshal config file failed: ", err)
	}

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatal("Open /proc/self/ns/net failed: ", err)
	}
	defer netns.Close()

	portData, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		log.Fatal("Read /proc/net/tcp failed: ", err)
	}
	for _, port := range config.PortMaps {
		inode := findInode(string(portData), port.DstPort)
		if inode == "" {
			log.Printf("Error finding inode for port: %d", port.DstPort)
			continue
		}
		pid, fd, err := findSocketOwner(inode)
		if err != nil {
			log.Printf("Error finding socket owner: %v", err)
			continue
		}

		sockFD, err := stealSocketFd(pid, fd)
		if err != nil {
			log.Printf("Error stealing socket fd: %v", err)
			continue
		}
		err = objs.PortsMap.Update(port.SrcPort, uint64(sockFD), ebpf.UpdateAny)
		unix.Close(sockFD)
		if err != nil {
			log.Printf("Error updating BPF objects: %v", err)
			continue
		}

		log.Printf("forwarding %d -> %d", port.SrcPort, port.DstPort)
	}

	lnk, err := link.AttachNetNs(int(netns.Fd()), objs.PortForwardLookupEchoDispatch)
	if err != nil {
		log.Fatal("Attach sk_lookup failed: ", err)
	}
	defer lnk.Close()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	log.Println("running, Ctrl+C to stop")
	<-sig
}

func findInode(tcpData string, port uint32) string {
	for _, line := range strings.Split(tcpData, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		p, _ := strconv.ParseUint(strings.Split(f[1], ":")[1], 16, 16)
		if uint16(p) == uint16(port) {
			return f[9]
		}
	}
	return ""
}

func findSocketOwner(inode string) (pid int, fd int, err error) {
	target := "socket:[" + inode + "]"
	paths, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, path := range paths {
		if l, err := os.Readlink(path); err == nil && l == target {
			res := strings.Split(path, "/")
			pid, err := strconv.Atoi(res[2])
			if err != nil {
				return -1, -1, err
			}
			fd, err := strconv.Atoi(res[4])
			if err != nil {
				return -1, -1, err
			}
			return pid, fd, nil
		}
	}
	return -1, -1, errors.New("no suitable socket owner")
}

func stealSocketFd(pid, fd int) (int, error) {
	pidFD, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pidFD)

	getfd, err := unix.PidfdGetfd(pidFD, fd, 0)
	if err != nil {
		return -1, err
	}

	return getfd, nil
}
