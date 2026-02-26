# BPF Learning/Testing

This repository hosts my personal implementations of BPF (Berkeley Packet Filter) tools and scripts for advanced Linux systems performance analysis.

## Prerequisites

To run these scripts, you need a Linux environment with:
* Root privileges (`sudo`)
* Python 3
* BCC tools installed (`bpfcc-tools` or `bcc-tools`)
* A kernel that supports eBPF (Linux 4.x+, recommended 5.x+)

## Usage

Most scripts require root access to load BPF programs into the kernel:

```bash
cd tsastat
sudo ./tsastat.py
```

## Acknowledgements

Special thanks to Brendan Gregg for his work and inspiration in the field of systems performance, and especially in BPF.

## Disclaimer

All code in this repository was written entirely by me for testing and educational purposes.<br>
The tool descriptions, however, were generated with the assistance of AI.
