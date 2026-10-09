#!/bin/sh
# Check cfrs's header encoding against cloudflared's own Go implementation.
#
# The oracle is a verbatim copy of SerializeHeaders from
# cloudflared's connection/header.go, using the same
# `headerEncoding = base64.RawStdEncoding`. Running it is the only way to be
# sure our encoder matches: reading the Go source is not the same as executing
# it, and the padding and separator rules are easy to get backwards.
#
# Two checks run:
#
#   1. Live: build and run the Go oracle, diff its output against ours.
#   2. Regression guard: diff our output against tools/header-oracle.txt, a
#      captured run of the same oracle. This runs without Go and without a
#      network, so it still catches a change to the encoding.
#
# Sandboxes often mount /tmp noexec, which stops the Go toolchain from linking
# or launching anything there. CF_ORACLE_TMP lets a caller point the scratch
# space somewhere exec-capable; it defaults to the first of $TMPDIR, the repo's
# own target directory, or /tmp that can actually execute a file.
#
# Usage: tools/check-header-oracle.sh [--recorded-only]

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

CARGO_HOME=${CARGO_HOME:-/workspace/.cargo-home}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$root/target}
export CARGO_HOME CARGO_TARGET_DIR

recorded_only=0
[ "${1:-}" = "--recorded-only" ] && recorded_only=1

# Pick a scratch directory that can actually execute a file.
scratch=""
for candidate in "${CF_ORACLE_TMP:-}" "$CARGO_TARGET_DIR" "$root/target" /workspace /tmp; do
    [ -n "$candidate" ] || continue
    probe="$candidate/.cfrs-exec-probe.$$"
    # A noexec mount refuses execution regardless of the file mode, so the
    # only honest probe is to run something.
    printf '#!/bin/sh\nexit 0\n' >"$probe" 2>/dev/null && chmod +x "$probe" 2>/dev/null
    if [ -x "$probe" ] && "$probe" 2>/dev/null; then
        scratch="$candidate"
        rm -f "$probe"
        break
    fi
    rm -f "$probe" 2>/dev/null || true
done
if [ -z "$scratch" ]; then
    echo "no exec-capable scratch directory found; set CF_ORACLE_TMP" >&2
    exit 1
fi

work=$(mktemp -d "$scratch/cf-oracle.XXXXXX")
trap 'rm -rf "$work"' EXIT

if ! command -v go >/dev/null 2>&1; then
    echo "go is not installed; falling back to the recorded oracle" >&2
    recorded_only=1
fi

if [ "$recorded_only" -eq 0 ]; then
    cat >"$work/go.mod" <<'EOF'
module oracle

go 1.21
EOF

    cat >"$work/main.go" <<'GOEOF'
package main

// Verbatim from cloudflared connection/header.go (master).
import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
)

var headerEncoding = base64.RawStdEncoding

type HTTPHeader struct{ Name, Value string }

func SerializeHeaders(h1Headers http.Header) string {
	serializedLen := 0
	for headerName, headerValues := range h1Headers {
		for _, headerValue := range headerValues {
			nameLen := headerEncoding.EncodedLen(len(headerName))
			valueLen := headerEncoding.EncodedLen(len(headerValue))
			const delims = 2
			serializedLen += delims + nameLen + valueLen
		}
	}
	_ = serializedLen

	var buf strings.Builder
	buf.Grow(serializedLen)

	temp := make([]byte, 256)
	writeB64 := func(s string) {
		n := headerEncoding.EncodedLen(len(s))
		if n > len(temp) {
			temp = make([]byte, n)
		}
		headerEncoding.Encode(temp[:n], []byte(s))
		buf.Write(temp[:n])
	}

	for headerName, headerValues := range h1Headers {
		for _, headerValue := range headerValues {
			if buf.Len() > 0 {
				buf.WriteByte(';')
			}
			writeB64(headerName)
			buf.WriteByte(':')
			writeB64(headerValue)
		}
	}

	return buf.String()
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", -1)
		names := parts[0]
		values := []string{}
		if len(parts) > 1 && parts[1] != "-" {
			values = strings.Split(parts[1], ",")
		}
		h := http.Header{}
		for i, n := range strings.Split(names, ",") {
			v := ""
			if i < len(values) {
				v = values[i]
			}
			h.Add(n, v)
		}
		enc := SerializeHeaders(h)
		// Go map order is randomized, so emit pairs sorted.
		ps := strings.Split(enc, ";")
		sort.Strings(ps)
		for _, e := range ps {
			fmt.Println(e)
		}
		fmt.Println("---")
	}
}
GOEOF

    # `go run` links into TMPDIR as well as GOTMPDIR, and TMPDIR is noexec in
    # some sandboxes, so build a binary and exec that instead.
    GOTMPDIR="$work" GOCACHE="$work/cache" TMPDIR="$work" go build -o "$work/oracle" "$work/main.go"

    "$work/oracle" <<'IN' >"$work/oracle.txt"
host|a
host|example.com
X-Binary|x
host,cf-connecting-ip|example.com,1.2.3.4
a,b,c|y,z,w
IN

    cargo run --quiet --example dump_headers 2>/dev/null >"$work/ours.txt"

    if diff -u "$work/oracle.txt" "$work/ours.txt"; then
        echo "PASS: header encoding matches cloudflared's SerializeHeaders (5 live cases)"
    else
        echo "FAIL: header encoding differs from cloudflared's SerializeHeaders" >&2
        exit 1
    fi
else
    echo "note: skipped the live Go comparison"
fi

ours=$(mktemp "$work/ours.XXXXXX")
cargo run --quiet --example dump_headers 2>/dev/null >"$ours"

if diff -u tools/header-oracle.txt "$ours"; then
    echo "PASS: header encoding still matches the recorded Go oracle"
else
    echo "FAIL: header encoding drifted from tools/header-oracle.txt" >&2
    echo "      if the change is intentional, re-record it with:" >&2
    echo "      tools/check-header-oracle.sh   # then copy the live oracle output" >&2
    exit 1
fi