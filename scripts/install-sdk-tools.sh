#!/usr/bin/env bash
# Installs the pinned toolchains of the Python and Go SDKs (M15, ADR 0030)
# into one directory, which `kronik build` finds as $KRONIK_SDK_TOOLS
# (default ~/.cache/kronik/sdk-tools):
#
#   componentize-py 0.25.1   Python components (the wheel, by SHA-256)
#   Go 1.27.2                TinyGo's Go toolchain (the archive, by SHA-256)
#   TinyGo 0.43.0            Go components (the archive, by SHA-256)
#   wit-bindgen-go v0.7.0    Go bindings, for SDK maintainers (Go's checksum
#                            database)
#   wasm-tools 1.262.0       which TinyGo runs to make the component
#                            (crates.io, --locked)
#   WASI-Virt bca61c27       the deny adapter for filesystem and sockets
#                            (git revision, built with --locked and Rust
#                            1.99.1, without wasm-opt)
#
# Each tool is installed once per version and left alone afterwards. Needs
# Linux x86_64, curl, python3 with pip, and cargo (rustup) for WASI-Virt
# and wasm-tools.
#
# Usage: scripts/install-sdk-tools.sh [--only python|go] [DIR]
set -euo pipefail

only=""
if [ "${1:-}" = "--only" ]; then
    only="${2:-}"
    case "$only" in python | go) ;; *) echo "usage: $0 [--only python|go] [DIR]" >&2; exit 2 ;; esac
    shift 2
fi
dir="${1:-${KRONIK_SDK_TOOLS:-$HOME/.cache/kronik/sdk-tools}}"
mkdir -p "$dir/bin" "$dir/downloads"
dir="$(cd "$dir" && pwd)"

if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
    echo "error: the pinned SDK toolchains are for Linux x86_64, not $(uname -s)-$(uname -m)" >&2
    exit 1
fi

COMPONENTIZE_PY=0.25.1
COMPONENTIZE_PY_WHEEL=componentize_py-0.25.1-cp39-abi3-manylinux_2_28_x86_64.whl
COMPONENTIZE_PY_SHA256=8623cd8cab8453cb0cd8bf03f3c7103420d06f2f3d360186a280a70a1ca5e89f
GO=1.27.2
GO_SHA256=ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5
TINYGO=0.43.0
TINYGO_SHA256=ca9fc6d055e3889462dea4450a2e42a92242d88b5c362a7ec39bdb563413d78a
WIT_BINDGEN_GO=v0.7.0
WASI_VIRT_REV=bca61c27499d2c290b5431cfcff013737b3ba01d
WASM_TOOLS=1.262.0
RUST=1.99.1

# fetch URL FILE SHA256: downloads once into downloads/ and checks the hash.
fetch() {
    local url=$1 file="$dir/downloads/$2" sha=$3
    if [ ! -f "$file" ]; then
        curl -fsSL --retry 3 -o "$file.part" "$url"
        mv "$file.part" "$file"
    fi
    if ! echo "$sha  $file" | sha256sum -c --quiet -; then
        rm -f "$file"
        echo "error: $2 does not have the pinned SHA-256 $sha" >&2
        exit 1
    fi
}

python_tools() {
    local target="$dir/componentize-py-$COMPONENTIZE_PY"
    if [ ! -d "$target" ]; then
        [ -f "$dir/downloads/$COMPONENTIZE_PY_WHEEL" ] ||
            pip3 download -q --no-deps --only-binary=:all: --platform manylinux_2_28_x86_64 \
                "componentize-py==$COMPONENTIZE_PY" -d "$dir/downloads"
        if ! echo "$COMPONENTIZE_PY_SHA256  $dir/downloads/$COMPONENTIZE_PY_WHEEL" | sha256sum -c --quiet -; then
            rm -f "$dir/downloads/$COMPONENTIZE_PY_WHEEL"
            echo "error: $COMPONENTIZE_PY_WHEEL does not have the pinned SHA-256" >&2
            exit 1
        fi
        # An interrupted install leaves a partial directory pip would keep.
        rm -rf "$target.part"
        pip3 install -q --no-deps --no-index --target "$target.part" "$dir/downloads/$COMPONENTIZE_PY_WHEEL"
        mv "$target.part" "$target"
    fi
    cat >"$dir/bin/componentize-py" <<EOF
#!/bin/sh
# componentize-py $COMPONENTIZE_PY, installed by scripts/install-sdk-tools.sh
PYTHONPATH="$target\${PYTHONPATH:+:\$PYTHONPATH}" exec python3 -c 'import sys; from componentize_py import script; sys.argv[0] = "componentize-py"; sys.exit(script())' "\$@"
EOF
    chmod +x "$dir/bin/componentize-py"
    echo "componentize-py $("$dir/bin/componentize-py" --version | awk '{print $2}')"
}

go_tools() {
    if [ ! -x "$dir/go-$GO/bin/go" ]; then
        fetch "https://go.dev/dl/go$GO.linux-amd64.tar.gz" "go$GO.linux-amd64.tar.gz" "$GO_SHA256"
        rm -rf "$dir/go-$GO.part" && mkdir "$dir/go-$GO.part"
        tar -xzf "$dir/downloads/go$GO.linux-amd64.tar.gz" -C "$dir/go-$GO.part" --strip-components=1
        mv "$dir/go-$GO.part" "$dir/go-$GO"
    fi
    ln -sfn "$dir/go-$GO/bin/go" "$dir/bin/go"
    ln -sfn "$dir/go-$GO/bin/gofmt" "$dir/bin/gofmt"
    if [ ! -x "$dir/tinygo-$TINYGO/bin/tinygo" ]; then
        fetch "https://github.com/tinygo-org/tinygo/releases/download/v$TINYGO/tinygo$TINYGO.linux-amd64.tar.gz" \
            "tinygo$TINYGO.linux-amd64.tar.gz" "$TINYGO_SHA256"
        rm -rf "$dir/tinygo-$TINYGO.part" && mkdir "$dir/tinygo-$TINYGO.part"
        tar -xzf "$dir/downloads/tinygo$TINYGO.linux-amd64.tar.gz" -C "$dir/tinygo-$TINYGO.part" --strip-components=1
        mv "$dir/tinygo-$TINYGO.part" "$dir/tinygo-$TINYGO"
    fi
    ln -sfn "$dir/tinygo-$TINYGO/bin/tinygo" "$dir/bin/tinygo"
    if [ ! -x "$dir/wasm-tools-$WASM_TOOLS/bin/wasm-tools" ]; then
        CARGO_TARGET_DIR="$dir/cargo-target" cargo "+$RUST" install -q --locked \
            --root "$dir/wasm-tools-$WASM_TOOLS.part" "wasm-tools@$WASM_TOOLS"
        rm -rf "$dir/wasm-tools-$WASM_TOOLS" && mv "$dir/wasm-tools-$WASM_TOOLS.part" "$dir/wasm-tools-$WASM_TOOLS"
        rm -rf "$dir/cargo-target"
    fi
    ln -sfn "$dir/wasm-tools-$WASM_TOOLS/bin/wasm-tools" "$dir/bin/wasm-tools"
    # One directory per version, so a version change installs it again.
    if [ ! -x "$dir/wit-bindgen-go-$WIT_BINDGEN_GO/wit-bindgen-go" ]; then
        rm -rf "$dir/wit-bindgen-go-$WIT_BINDGEN_GO.part"
        GOBIN="$dir/wit-bindgen-go-$WIT_BINDGEN_GO.part" GOPATH="$dir/gopath" GOFLAGS=-modcacherw GOTOOLCHAIN=local \
            "$dir/bin/go" install "go.bytecodealliance.org/cmd/wit-bindgen-go@$WIT_BINDGEN_GO"
        mv "$dir/wit-bindgen-go-$WIT_BINDGEN_GO.part" "$dir/wit-bindgen-go-$WIT_BINDGEN_GO"
    fi
    ln -sfn "$dir/wit-bindgen-go-$WIT_BINDGEN_GO/wit-bindgen-go" "$dir/bin/wit-bindgen-go"
    echo "go $("$dir/bin/go" env GOVERSION), tinygo $("$dir/bin/tinygo" version | awk '{print $3}'), wit-bindgen-go $("$dir/bin/wit-bindgen-go" --version | awk '{print $3}'), wasm-tools $("$dir/bin/wasm-tools" --version | awk '{print $2}')"
}

virt() {
    local target="$dir/wasi-virt-${WASI_VIRT_REV:0:8}"
    if [ ! -x "$target/bin/wasi-virt" ]; then
        CARGO_TARGET_DIR="$dir/cargo-target" cargo "+$RUST" install -q --locked --no-default-features \
            --root "$target.part" --git https://github.com/bytecodealliance/WASI-Virt --rev "$WASI_VIRT_REV" wasi-virt
        rm -rf "$target" && mv "$target.part" "$target" && rm -rf "$dir/cargo-target"
    fi
    ln -sfn "$target/bin/wasi-virt" "$dir/bin/wasi-virt"
    echo "wasi-virt ${WASI_VIRT_REV:0:8}"
}

case "$only" in
    python) python_tools ;;
    go) go_tools ;;
    *) python_tools; go_tools ;;
esac
virt
echo "installed in $dir (kronik build reads \$KRONIK_SDK_TOOLS, default ~/.cache/kronik/sdk-tools)"
