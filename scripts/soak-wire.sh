#!/usr/bin/env bash
# soak-wire.sh — sustained-load soak for the inline wire firewall (a3s-gateway `wire` + a3s-sentry).
#
# Drives the proxy with many concurrent secret-bearing requests and asserts the security + stability
# contract under load: the secret NEVER reaches the upstream (masked), the response is restored, the
# proxy's RSS stays flat (no leak), and it never crashes. Pure userspace — runs anywhere the wire build
# does. Exercises both the inline gate (`inspect_wire` on every request) and the hyper transport.
#
#   ./scripts/soak-wire.sh [path/to/a3s-gateway] [duration_seconds] [concurrency]
#
# Build the binary first:  cargo build --features wire --bin a3s-gateway
set -u
BIN="${1:-./target/debug/a3s-gateway}"
DUR="${2:-30}"
CONC="${3:-32}"

if [ ! -x "$BIN" ]; then
  echo "soak-wire: binary not found: $BIN (build: cargo build --features wire --bin a3s-gateway)" >&2
  exit 2
fi

exec python3 - "$BIN" "$DUR" "$CONC" <<'PY'
import sys, time, socket, subprocess, threading, http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN, DUR, CONC = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
SECRET = "sk-SOAKSECRET0123456789abcdef"
leaked = threading.Event()

# Mock upstream: echo the (masked) body back; flag if the real secret ever arrives.
class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, so the proxy->upstream conn is reused
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        if SECRET.encode() in body:
            leaked.set()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

up = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
up_port = up.server_address[1]
threading.Thread(target=up.serve_forever, daemon=True).start()

# Grab a free port for the proxy.
s = socket.socket(); s.bind(("127.0.0.1", 0)); proxy_port = s.getsockname()[1]; s.close()

proc = subprocess.Popen(
    [BIN, "wire", "--listen", f"127.0.0.1:{proxy_port}", "--upstream", f"http://127.0.0.1:{up_port}"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)

# Wait for the proxy to accept connections.
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", proxy_port), 0.2).close(); break
    except OSError:
        if proc.poll() is not None:
            print("FAIL: proxy exited during startup, rc", proc.returncode); sys.exit(1)
        time.sleep(0.1)
else:
    print("FAIL: proxy never came up"); proc.kill(); sys.exit(1)

stop = time.time() + DUR
counts = {"ok": 0, "err": 0, "restored": 0}
lock = threading.Lock()
body = ('{"messages":[{"role":"user","content":"deploy with %s and mail a@b.com"}]}' % SECRET).encode()

def worker():
    local = {"ok": 0, "err": 0, "restored": 0}
    conn = None
    while time.time() < stop:
        try:
            if conn is None:
                conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
            conn.request("POST", "/wire/soak/v1/messages", body, {"Content-Type": "application/json"})
            r = conn.getresponse(); data = r.read()  # keep-alive: don't close between requests
            if r.status == 200:
                local["ok"] += 1
                if SECRET.encode() in data:
                    local["restored"] += 1
            else:
                local["err"] += 1
        except Exception:
            local["err"] += 1
            try: conn.close()
            except Exception: pass
            conn = None
    with lock:
        for k in counts:
            counts[k] += local[k]

def rss_kb(pid):
    try:
        return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)]).strip())
    except Exception:
        return -1

threads = [threading.Thread(target=worker) for _ in range(CONC)]
for t in threads: t.start()

samples = []
while time.time() < stop:
    if proc.poll() is not None:
        print("FAIL: proxy crashed mid-soak, rc", proc.returncode); sys.exit(1)
    samples.append(rss_kb(proc.pid))
    time.sleep(1)
for t in threads: t.join()

alive = proc.poll() is None
proc.terminate()
try: proc.wait(5)
except Exception: proc.kill()

samples = [s for s in samples if s > 0]
steady = samples[3:] or samples  # drop warm-up samples
rss_min = min(steady) if steady else -1
rss_max = max(steady) if steady else -1
growth = (rss_max / rss_min) if rss_min > 0 else 0.0

print(f"soak-wire: {DUR:.0f}s  concurrency={CONC}")
print(f"  requests: ok={counts['ok']}  err={counts['err']}  restored={counts['restored']}  "
      f"({counts['ok']/DUR:.0f} req/s)")
print(f"  proxy RSS KB (steady): min={rss_min} max={rss_max} growth={growth:.2f}x  (samples={len(steady)})")
print(f"  proxy alive at end: {alive}")
print(f"  secret leaked to upstream: {leaked.is_set()}")

fail = []
if not alive: fail.append("proxy died")
if leaked.is_set(): fail.append("SECRET REACHED UPSTREAM (masking broke under load)")
if counts["ok"] == 0: fail.append("no successful requests")
if counts["err"] > max(1, counts["ok"] * 0.01): fail.append(f"high error rate ({counts['err']})")
if counts["restored"] != counts["ok"]: fail.append(f"restore mismatch ({counts['restored']}/{counts['ok']})")
if rss_min > 0 and growth > 1.5: fail.append(f"RSS grew {growth:.2f}x (possible leak)")

if fail:
    print("RESULT: FAIL —", "; ".join(fail)); sys.exit(1)
print("RESULT: PASS — masked under load, restored, flat RSS, no crash")
PY
