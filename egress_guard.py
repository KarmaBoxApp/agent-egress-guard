# -*- coding: utf-8 -*-
"""agent-egress-guard: a small outbound request check for AI agent tools.

Standard library only. Everything runs on 127.0.0.1.

- capture: a local HTTP server that only logs what it receives (stands in for "a website the agent visits").
- guard:   a local forwarding proxy. Before a request leaves, it scans the request line (including the
           decoded URL) and every header. If it finds an email address, a key-shaped string, or a value
           you registered in DENY, it answers 403 and does not forward. Otherwise it forwards to capture.

Usage:  python3 egress_guard.py <an empty working directory>

All test data is placeholder data (demo.user@example.invalid, a fake sk-test string).
The script does not read any real identity information.
This is not a reproduction of any vendor's internals. It demonstrates one technique:
checking outbound requests in code, outside the model.
"""
import base64, http.client, http.server, json, os, re, socket, subprocess, sys, threading, time, urllib.parse

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
KEYS = [re.compile(p) for p in (r"\bsk-[A-Za-z0-9_-]{16,}", r"\bAKIA[0-9A-Z]{16}\b", r"\bghp_[A-Za-z0-9]{36}\b")]
DENY = {"demo.user@example.invalid"}          # values you know sit in the agent's context


def findings(text):
    hits = []
    if any(s in text for s in DENY):
        hits.append("denylist")
    if EMAIL.search(text):
        hits.append("email")
    if any(k.search(text) for k in KEYS):
        hits.append("key")
    return hits


def inspect(request_line, headers):
    target = request_line.split(" ")[1] if " " in request_line else request_line
    decoded = urllib.parse.unquote_plus(target)
    hits = [("url", h) for h in findings(decoded)]
    for k, v in headers.items():
        hits += [("header:" + k, h) for h in findings(v)]
    return hits


class Capture(http.server.BaseHTTPRequestHandler):
    log_path = None

    def do_GET(self):
        with open(self.log_path, "a") as f:
            f.write(json.dumps({"path": self.path, "ua": self.headers.get("User-Agent")}) + "\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok\n")

    def log_message(self, *a):
        pass


class Guard(http.server.BaseHTTPRequestHandler):
    upstream = None
    blocked = []

    def do_GET(self):
        hits = inspect(self.requestline, dict(self.headers))
        if hits:
            Guard.blocked.append(hits)
            self.send_response(403); self.end_headers()
            self.wfile.write(("blocked: " + ", ".join(f"{w}={h}" for w, h in hits) + "\n").encode())
            return
        u = urllib.parse.urlsplit(self.path)
        conn = http.client.HTTPConnection(*self.upstream, timeout=5)
        path = u.path + ("?" + u.query if u.query else "")
        conn.request("GET", path, headers={k: v for k, v in self.headers.items() if k.lower() != "proxy-connection"})
        r = conn.getresponse(); body = r.read()
        self.send_response(r.status); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve(handler):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def curl(proxy, url, *extra):
    # gotcha: if NO_PROXY contains 127.0.0.1/localhost, curl silently bypasses -x; --noproxy "" clears it
    r = subprocess.run(["curl", "-s", "-o", "-", "-w", "|%{http_code}", "-x", proxy, "--noproxy", "", *extra, url],
                       capture_output=True, text=True, timeout=10)
    body, code = r.stdout.rsplit("|", 1)
    return code, body.strip()


def main(workdir):
    assert os.path.isdir(workdir) and not os.listdir(workdir), "need a fresh empty directory"
    Capture.log_path = os.path.join(workdir, "capture.log")
    cap = serve(Capture); Guard.upstream = cap.server_address
    g = serve(Guard)
    proxy = "http://%s:%d" % g.server_address
    site = "http://%s:%d" % cap.server_address
    b64 = base64.b64encode(b"demo.user@example.invalid").decode()
    cases = [
        ("default curl", "/search?q=weather", []),
        ("bot UA with contact URL", "/page", ["-A", "my-agent/1.0 (+https://example.invalid/bot)"]),
        ("@handle in path", "/users/@octocat", []),
        ("email in User-Agent", "/page", ["-A", "my-session/1 <demo.user@example.invalid>"]),
        ("email in query, URL-encoded", "/track?u=demo.user%40example.invalid", []),
        ("key-shaped header", "/api", ["-H", "X-Api-Key: sk-test-AAAAAAAAAAAAAAAAAAAA"]),
        ("same email, base64 in header", "/page", ["-H", "X-Ref: " + b64]),
    ]
    print(f"capture={site} guard={proxy}")
    for name, path, extra in cases:
        code, body = curl(proxy, site + path, *extra)
        print(f"{name:32s} -> {code}  {body[:70]}")
    with open(Capture.log_path) as f:
        logged = [json.loads(l) for l in f]
    print("requests that reached the capture server:", len(logged))
    for l in logged:
        print("   ", l)
    # overhead: 200 sequential requests, direct vs through guard
    def timeit(via):
        t = time.perf_counter()
        for _ in range(200):
            c = http.client.HTTPConnection(*via, timeout=5)
            c.request("GET", (site + "/t") if via == g.server_address else "/t"); c.getresponse().read(); c.close()
        return time.perf_counter() - t
    d = timeit(cap.server_address); p = timeit(g.server_address)
    print(f"200 requests direct: {d:.3f}s   through guard: {p:.3f}s   per-request overhead: {(p-d)/200*1000:.2f} ms")
    g.shutdown(); cap.shutdown()


if __name__ == "__main__":
    main(sys.argv[1])
