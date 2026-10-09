#!/bin/bash
# End-to-end proof: expose a unix-socket origin on the public web.
#
# Everything runs in one process group because the sandbox reaps children
# between tool invocations. Steps:
#   1. start the unix-socket origin
#   2. self-check the origin directly over its socket (baseline)
#   3. start `cfrs serve`, which opens an SSH remote forward over the CONNECT
#      proxy and splices each visitor channel to the socket
#   4. fetch the public URL from a fresh HTTP client
#   5. fetch it a second time to prove a fresh marker (real traversal)
set -u
BIN=/workspace/cfrs/target/debug/cfrs
ORIGIN=/workspace/cfrs/target/cf-origin
SOCK=/tmp/cfrs-app.sock
PROXY="${HTTPS_PROXY#http://}"
PROXY="${PROXY#https://}"
OUT=/tmp/proof-out
mkdir -p "$OUT"
rm -f "$SOCK"

echo "== 1. start unix-socket origin =="
"$ORIGIN" --socket "$SOCK" > "$OUT/origin.log" 2>&1 &
ORIGIN_PID=$!
sleep 1
echo "origin pid=$ORIGIN_PID  socket=$SOCK"
ls -la "$SOCK"

echo
echo "== 2. baseline: origin directly over its unix socket =="
curl -sS --unix-socket "$SOCK" http://localhost/baseline | sed 's/^/  /'

echo
echo "== 3. start cfrs serve (SSH remote forward over CONNECT proxy) =="
"$BIN" serve --unix-socket "$SOCK" --proxy "$PROXY" > "$OUT/serve.log" 2>&1 &
SERVE_PID=$!
echo "cfrs pid=$SERVE_PID"

# Wait for a URL to appear on stdout.
URL=""
for i in $(seq 1 40); do
  if grep -q '^url:' "$OUT/serve.log" 2>/dev/null; then
    URL=$(grep '^url:' "$OUT/serve.log" | head -1 | awk '{print $2}')
    PORT=$(grep '^port:' "$OUT/serve.log" | head -1 | awk '{print $2}')
    break
  fi
  if ! kill -0 "$SERVE_PID" 2>/dev/null; then
    echo "cfrs exited early. log:"; sed 's/^/  /' "$OUT/serve.log"; exit 1
  fi
  sleep 1
done

if [ -z "$URL" ]; then
  echo "no URL after 40s. log:"; sed 's/^/  /' "$OUT/serve.log"; kill "$SERVE_PID" "$ORIGIN_PID" 2>/dev/null; exit 1
fi
echo "public URL = $URL  (remote port $PORT)"

echo
echo "== 4. fetch the public URL from a fresh client =="
# The public hostname resolves and is fetched through the same egress proxy,
# which is a genuinely external path: proxy -> pinggy edge -> SSH channel ->
# unix socket origin -> response.
FETCH="$URL/proof?via=public"
echo "GET $FETCH"
curl -sS -m 60 "$FETCH" -o "$OUT/body1.txt" -w '  http=%{http_code} time=%{time_total}s\n' 2>&1 | sed 's/^/  /'
echo "  --- body ---"; sed 's/^/  /' "$OUT/body1.txt"

echo
echo "== 5. fetch again (a fresh marker proves a real traversal) =="
curl -sS -m 60 "$URL/proof?via=second" -o "$OUT/body2.txt" -w '  http=%{http_code} time=%{time_total}s\n' 2>&1 | sed 's/^/  /'
echo "  --- body ---"; sed 's/^/  /' "$OUT/body2.txt"

echo
echo "== summary =="
if grep -q 'cf-origin OK' "$OUT/body1.txt" && grep -q 'cf-origin OK' "$OUT/body2.txt"; then
  echo "PASS: the public URL served the unix-socket origin through the tunnel."
else
  echo "FAIL: the public URL did not return the origin's response."
fi
echo "  origin marker 1: $(grep marker "$OUT/body1.txt" 2>/dev/null)"
echo "  origin marker 2: $(grep marker "$OUT/body2.txt" 2>/dev/null)"

kill "$SERVE_PID" "$ORIGIN_PID" 2>/dev/null
echo
echo "serve.log:"; sed 's/^/  /' "$OUT/serve.log"