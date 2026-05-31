import threading
from mitmproxy import http

_lock    = threading.Lock()
_queue   = []
_history = []

class InterceptAddon:
    def request(self, flow: http.HTTPFlow):
        raw = _build_raw_request(flow.request)
        entry = {
            "id":          id(flow),
            "method":      flow.request.method,
            "url":         flow.request.pretty_url,
            "raw_request": raw,
            "flow":        flow,
        }
        with _lock:
            _history.append(entry)
            _queue.append(entry)
        flow.intercept()

addon = InterceptAddon()

def _build_raw_request(req):
    # req.http_version is already like "HTTP/2.0" or "HTTP/1.1" — don't prefix again
    ver = req.http_version if str(req.http_version).startswith("HTTP/") else f"HTTP/{req.http_version}"
    first = f"{req.method} {req.path} {ver}\r\n"

    # HTTP/2 splits cookies into multiple header frames; mitmproxy's headers
    # collapse duplicate names by joining with ", " (a comma), which is INVALID
    # for the Cookie header (must be "; "). Rebuild Cookie crumbs with semicolons.
    header_lines = []
    for k, v in req.headers.items():
        if k.lower() == "cookie":
            # Split any comma-joined crumbs and re-join with the correct "; "
            crumbs = [c.strip() for c in v.replace(", ", ";").split(";") if c.strip()]
            v = "; ".join(crumbs)
        header_lines.append(f"{k}: {v}\r\n")
    headers = "".join(header_lines)

    body = req.content.decode(errors="replace") if req.content else ""
    return first + headers + "\r\n" + body

def get_queue():
    with _lock:
        return [{"id": e["id"], "method": e["method"],
                 "url": e["url"], "raw_request": e["raw_request"]}
                for e in _queue]

def get_history():
    with _lock:
        return [{"id": e["id"], "method": e["method"],
                 "url": e["url"], "raw_request": e["raw_request"]}
                for e in _history]

def forward(flow_id):
    entry = None
    with _lock:
        entry = next((e for e in _queue if e["id"] == flow_id), None)
        if entry:
            _queue.remove(entry)
    # lock is released BEFORE resume() to avoid deadlock
    if entry:
        entry["flow"].resume()

def drop(flow_id):
    entry = None
    with _lock:
        entry = next((e for e in _queue if e["id"] == flow_id), None)
        if entry:
            _queue.remove(entry)
    # lock is released BEFORE kill() to avoid deadlock
    if entry:
        entry["flow"].kill()