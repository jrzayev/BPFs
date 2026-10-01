#!/bin/bash

TOOL_NAME="$1"

if [ -z "$TOOL_NAME" ]; then
    echo "Usage: $0 <tool-name>"
    exit 1
fi

if [ -d "$TOOL_NAME" ]; then
    echo "Error: directory '$TOOL_NAME' already exists."
    exit 1
fi

DATE=$(date +"%-m/%-d/%Y")

mkdir "$TOOL_NAME"

for FILE in "$TOOL_NAME/$TOOL_NAME.c" "$TOOL_NAME/gen.go" "$TOOL_NAME/main.go"; do
    cat > "$FILE" <<EOF
//
// Crated by Javid Rzayev $DATE
//

EOF
done

(
    cd "$TOOL_NAME" || exit 1

    go mod init "github.com/jrzayev/BPFs/${TOOL_NAME}"

    go get github.com/cilium/ebpf
    go install github.com/cilium/ebpf/cmd/bpf2go@latest
)
