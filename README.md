# BPF Learning/Testing

This repository hosts my personal implementations of BPF (Berkeley Packet Filter) tools and scripts for advanced Linux systems performance analysis.

## Prerequisites

To run these tools, you need a Linux environment with:
* Root privileges (`sudo`)
* A kernel that supports eBPF (Linux 5.5+ and my personal opinion recommended 6.x or 7.x)

Depending on the tool:
* **Python/BCC tools** - Python 3 and BCC installed (`bpfcc-tools` or `bcc-tools`)
* **C/libbpf tools built with eunomia** - the [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) toolchain: `ecc` (compiler) and `ecli` (runner)
* **C/libbpf tools built with make** - `clang`, `llvm`, `libbpf-dev`, `bpftool`, `libelf-dev`, `zlib1g-dev`

## Usage

Most tools require root access to load BPF programs into the kernel.

### Python/BCC tools

```bash
cd tsastat
sudo ./tsastat.py
```

### C/libbpf tools (ecc + ecli)

Compile the BPF source into a package, then run it:

```bash
cd openlat
ecc openlat.c openlat.h
sudo ecli run package.json
```

### C/libbpf tools (make)

```bash
cd acceptlat
make
sudo ./acceptlat
```

## Acknowledgements

Special thanks to Brendan Gregg for his work and inspiration in the field of systems performance, and especially in BPF.

Thanks to the [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) project for the `ecc`/`ecli` toolchain and the [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial), which the C/libbpf tools here are built with and learned from.

## Disclaimer

All code in this repository was written entirely by me for testing and educational purposes.<br>
But for some tool descriptions, however, were generated with the assistance of AI.
