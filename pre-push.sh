#!/bin/sh
# remove compiled binaries and bpf2go output before push

TARGET="./"

find "$TARGET" -name .git -prune -o -type f -exec file -F '|' {} + \
| awk -F'|' '
    /Mach-O 64-bit executable arm64/ ||
    /ELF 64-bit LSB (pie )?executable/ ||
    /ELF 64-bit LSB relocatable, eBPF/ { print $1 }
' \
| while IFS= read -r f; do
    echo "pre-push: removing binary $f"
    rm -f "$f"
done

find "$TARGET" -name .git -prune -o -type f -name 'bpf_*_bpfel.go' -print \
| while IFS= read -r f; do
    echo "pre-push: removing generated $f"
    rm -f "$f"
done

exit 0
