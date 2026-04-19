from flask import Flask, render_template, request, redirect, url_for, session, json
import csv
import os
import threading
import time
import psutil
import requests as req_lib
from requests.exceptions import RequestException

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

TASKS_FILE = "tasks.csv"
FIELDNAMES = ["id", "name", "status", "progress", "total", "speed", "code", "cpu_usage"]

# ─── In-memory runtime state ─────────────────────────────────────────────────
# Holds live data for running tasks so we avoid CSV reads/writes in hot paths.
# Structure: { task_id: { "progress": int, "total": int, "speed": int,
#                         "status": str, "semaphore": threading.Semaphore } }
_runtime = {}
_runtime_lock = threading.Lock()


def _runtime_get(task_id, key, default=None):
    with _runtime_lock:
        return _runtime.get(task_id, {}).get(key, default)


def _runtime_set(task_id, key, value):
    with _runtime_lock:
        if task_id not in _runtime:
            _runtime[task_id] = {}
        _runtime[task_id][key] = value


# ─── CSV helpers ─────────────────────────────────────────────────────────────
_csv_lock = threading.Lock()


def load_tasks():
    tasks = []
    if not os.path.exists(TASKS_FILE):
        return tasks
    with _csv_lock:
        with open(TASKS_FILE, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tasks.append(row)
    return tasks


def save_tasks(tasks):
    with _csv_lock:
        with open(TASKS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(tasks)


def get_task(task_id):
    for t in load_tasks():
        if int(t["id"]) == task_id:
            return t
    return None


def update_task_fields(task_id, **fields):
    """Update specific fields of a task in the CSV atomically."""
    with _csv_lock:
        tasks = []
        if os.path.exists(TASKS_FILE):
            with open(TASKS_FILE, "r", newline="", encoding="utf-8") as f:
                tasks = list(csv.DictReader(f))
        for t in tasks:
            if int(t["id"]) == task_id:
                t.update({k: v for k, v in fields.items()})
        with open(TASKS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(tasks)


# ─── Thread class ─────────────────────────────────────────────────────────────

class MyThread(threading.Thread):
    def __init__(self, task_id, code, speed):
        super().__init__()
        self.task_id = task_id
        self.stop_event = threading.Event()
        self.code = code
        self.daemon = True

        # Build semaphore for speed control
        speed = max(1, int(speed))
        sem = threading.Semaphore(speed)
        with _runtime_lock:
            _runtime[task_id] = {
                "speed": speed,
                "semaphore": sem,
                "status": "Running",
            }

    def run(self):
        final_status = "Stopped"
        try:
            exec(self.code, {"stop_event": self.stop_event, "task": self})
            # If we get here without stop_event being set, task completed
            if not self.stop_event.is_set():
                final_status = "Done"
        except Exception as e:
            print(f"[Task {self.task_id}] Error: {e}")
            final_status = "Error"
        finally:
            _runtime_set(self.task_id, "status", final_status)
            # Persist final state to CSV
            progress = _runtime_get(self.task_id, "progress", 0)
            total = _runtime_get(self.task_id, "total", 1)
            update_task_fields(self.task_id, status=final_status,
                               progress=progress, total=total)

    # ── methods callable from exec'd code ────────────────────────────────────

    def get_speed(self):
        """Return current speed from in-memory state — no CSV read."""
        return str(_runtime_get(self.task_id, "speed", 1))

    def change_speed(self, new_speed):
        new_speed = max(1, int(new_speed))
        with _runtime_lock:
            state = _runtime.get(self.task_id, {})
            old_speed = state.get("speed", 1)
            state["speed"] = new_speed
            sem = state.get("semaphore")
            if sem is not None:
                diff = new_speed - old_speed
                if diff > 0:
                    # Allow more concurrent threads
                    for _ in range(diff):
                        sem.release()
                # If reducing speed, existing threads finish naturally;
                # new ones will be blocked by the semaphore count.
                # We adjust the internal counter carefully:
                elif diff < 0:
                    # Drain excess permits (non-blocking)
                    for _ in range(-diff):
                        sem.acquire(blocking=False)

    def load_progress(self):
        """Return saved progress from CSV (used only at task start)."""
        t = get_task(self.task_id)
        return t["progress"] if t else "0"

    def save_progress(self, progress):
        """Update progress in memory only; flush to CSV periodically."""
        _runtime_set(self.task_id, "progress", progress)
        # Persist every 5 saves to reduce CSV I/O
        with _runtime_lock:
            state = _runtime.get(self.task_id, {})
            count = state.get("_save_counter", 0) + 1
            state["_save_counter"] = count
            if count % 5 == 0:
                update_task_fields(self.task_id, progress=progress)

    def update_total_batch(self, total):
        _runtime_set(self.task_id, "total", total)
        update_task_fields(self.task_id, total=total)

    def acquire_slot(self):
        """Worker threads call this instead of the busy-wait loop."""
        sem = _runtime_get(self.task_id, "semaphore")
        if sem:
            sem.acquire()

    def release_slot(self):
        """Worker threads call this when done."""
        sem = _runtime_get(self.task_id, "semaphore")
        if sem:
            sem.release()

    def stop(self):
        self.stop_event.set()


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        if request.form["username"] == "yogesh" and request.form["password"] == "password":
            session["username"] = request.form["username"]
            return redirect(url_for("dashboard"))
        return render_template("signin.html", error="Invalid username or password")
    return render_template("signin.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin"))


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("signin"))
    tasks = load_tasks()
    return render_template("dashboard.html", tasks=tasks)


# ─── Task CRUD ────────────────────────────────────────────────────────────────

@app.route("/add-task", methods=["POST"])
def add_task():
    if "username" not in session:
        return redirect(url_for("signin"))

    if request.is_json:
        data = request.get_json()
        task_name = data.get("name", "New Task")
        code = data.get("code", "")
        speed = data.get("speed", 1)
    else:
        task_name = request.form.get("name", "New Task")
        code = request.form.get("code", "")
        speed = request.form.get("speed", 1)

    tasks = load_tasks()
    ids = [int(t["id"]) for t in tasks]
    new_id = max(ids) + 1 if ids else 1

    tasks.append({
        "id": str(new_id),
        "name": task_name,
        "status": "Stopped",
        "progress": 0,
        "total": 1,
        "speed": speed,
        "code": code,
        "cpu_usage": ""
    })
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/delete/<int:task_id>", methods=["POST"])
def delete_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
    # Remove from runtime state
    with _runtime_lock:
        _runtime.pop(task_id, None)
    tasks = [t for t in load_tasks() if int(t["id"]) != task_id]
    save_tasks(tasks)
    outfile = f"file_{task_id}"
    if os.path.exists(outfile):
        os.remove(outfile)
    return redirect(url_for("dashboard"))


@app.route("/restart/<int:task_id>", methods=["POST"])
def restart_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    # Stop if running
    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
    with _runtime_lock:
        _runtime.pop(task_id, None)
    update_task_fields(task_id, progress=0, status="Stopped")
    outfile = f"file_{task_id}"
    if os.path.exists(outfile):
        os.remove(outfile)
    return redirect(url_for("dashboard"))


# ─── Task control ─────────────────────────────────────────────────────────────

# Lock per task to prevent double-starts
_start_locks = {}
_start_locks_lock = threading.Lock()


def get_start_lock(task_id):
    with _start_locks_lock:
        if task_id not in _start_locks:
            _start_locks[task_id] = threading.Lock()
        return _start_locks[task_id]


@app.route("/start/<int:task_id>")
def start_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    lock = get_start_lock(task_id)
    if not lock.acquire(blocking=False):
        return "<script>alert('Task start already in progress'); window.location.href='/dashboard'</script>"

    try:
        tasks = load_tasks()
        for t in tasks:
            if int(t["id"]) == task_id:
                # Check in-memory status first (more accurate than CSV)
                live_status = _runtime_get(task_id, "status")
                if live_status == "Running" or t["status"] == "Running":
                    return "<script>alert('Task is already running'); window.location.href='/dashboard'</script>"
                t["status"] = "Running"
                thread = MyThread(task_id, t["code"], t["speed"])
                thread.start()
                save_tasks(tasks)
                return redirect(url_for("dashboard"))
    finally:
        lock.release()

    return redirect(url_for("dashboard"))


@app.route("/stop/<int:task_id>")
def stop_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    stopped = False
    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
            stopped = True

    if stopped:
        _runtime_set(task_id, "status", "Stopped")
        # Flush current progress to CSV
        progress = _runtime_get(task_id, "progress", 0)
        update_task_fields(task_id, status="Stopped", progress=progress)
        return redirect(url_for("dashboard"))

    return "<script>alert('Task is not running'); window.location.href='/dashboard'</script>"


# ─── Speed control ────────────────────────────────────────────────────────────

@app.route("/increase-speed/<int:task_id>")
def increase_speed(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            new_speed = int(t["speed"]) + 1
            t["speed"] = new_speed
            # Update running thread via change_speed (handles semaphore)
            for thread in threading.enumerate():
                if isinstance(thread, MyThread) and thread.task_id == task_id:
                    thread.change_speed(new_speed)
            # Also update in-memory if thread not found
            _runtime_set(task_id, "speed", new_speed)
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/decrease-speed/<int:task_id>")
def decrease_speed(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            new_speed = max(1, int(t["speed"]) - 1)
            t["speed"] = new_speed
            for thread in threading.enumerate():
                if isinstance(thread, MyThread) and thread.task_id == task_id:
                    thread.change_speed(new_speed)
            _runtime_set(task_id, "speed", new_speed)
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


# ─── Code editor ──────────────────────────────────────────────────────────────

@app.route("/edit/<int:task_id>")
def edit_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    t = get_task(task_id)
    if t:
        return render_template("editor.html", task=t, code=t["code"])
    return redirect(url_for("dashboard"))


@app.route("/save/<int:task_id>", methods=["POST"])
def save_code(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    update_task_fields(task_id, code=request.form["code"])
    return redirect(url_for("dashboard"))


# ─── Output file viewer ───────────────────────────────────────────────────────

@app.route("/file_<task_id>")
def get_file(task_id):
    if "username" not in session:
        return "Unauthorized", 401
    filename = f"file_{task_id}"
    if os.path.exists(filename):
        # Cap read at 2MB to avoid massive responses
        with open(filename, "r", errors="ignore") as f:
            content = f.read(2 * 1024 * 1024)
        return content, 200, {"Content-Type": "text/plain"}
    return "No output yet.", 404


# ─── CPU usage (AJAX) ─────────────────────────────────────────────────────────

@app.route("/cpu-usage")
def cpu_usage():
    return json.dumps({"cpu_usage": psutil.cpu_percent(interval=0.5)})


# ─── Task status (AJAX polling) — served from memory, no CSV read ─────────────

@app.route("/task-status")
def task_status():
    tasks = load_tasks()
    result = []
    for t in tasks:
        task_id = int(t["id"])
        # Prefer live in-memory values if the task is running
        live = _runtime.get(task_id, {})
        progress = live.get("progress", int(t.get("progress", 0)))
        total = live.get("total", max(int(t.get("total", 1)), 1))
        speed = live.get("speed", t["speed"])
        status = live.get("status", t["status"])
        total = max(total, 1)
        pct = round((progress / total) * 100, 1)
        result.append({
            "id": t["id"],
            "status": status,
            "progress": pct,
            "speed": speed,
        })
    return json.dumps(result)


# ─── Tool routes ──────────────────────────────────────────────────────────────

def _create_tool_task(name, code, speed):
    """Helper to append a tool task to the CSV and redirect."""
    tasks = load_tasks()
    ids = [int(t["id"]) for t in tasks]
    new_id = max(ids) + 1 if ids else 1
    tasks.append({
        "id": str(new_id), "name": name, "status": "Stopped",
        "progress": 0, "total": 1, "speed": speed, "code": code, "cpu_usage": ""
    })
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/nmap", methods=["POST"])
def nmap():
    if "username" not in session:
        return redirect(url_for("signin"))
    ip = request.form.get("ip", "").strip()
    if not ip:
        return redirect(url_for("dashboard"))
    all_ports = request.form.get("all_ports")
    start_port = request.form.get("start_port", "0").strip()
    end_port = request.form.get("end_port", "1024").strip()

    with open("nmap", "r") as f:
        code = f.read()

    if all_ports:
        code = code.replace("start_range", "0").replace("end_range", "65535")
        speed = 500
    else:
        code = code.replace("start_range", start_port).replace("end_range", end_port)
        speed = 100

    # Use repr() to safely embed the IP string
    code = code.replace('"ip_goes_here"', repr(ip))
    return _create_tool_task(f"nmap_{ip}", code, speed)


@app.route("/dirbuster", methods=["POST"])
def dirbuster():
    if "username" not in session:
        return redirect(url_for("signin"))
    data = request.get_json()
    url = data.get("url", "").strip()
    status_codes = data.get("excludedstatuscodes", [])

    with open("dirbuster", "r") as f:
        code = f.read()

    code = code.replace('"url_goes_here"', repr(url))
    code = code.replace("array_status_code", repr(status_codes))
    return _create_tool_task(f"dirbuster_{url}", code, 500)


@app.route("/httpx", methods=["POST"])
def httpx():
    if "username" not in session:
        return redirect(url_for("signin"))
    data = request.get_json()
    targets = data.get("targets", "").strip()

    with open("httpx", "r") as f:
        code = f.read()

    # targets is a multiline string — embed safely
    code = code.replace('"""targets_goes_here"""', repr(targets))
    return _create_tool_task("httpx_probe", code, 100)


@app.route("/subfinder", methods=["POST"])
def subfinder():
    if "username" not in session:
        return redirect(url_for("signin"))
    data = request.get_json()
    domain = data.get("domain", "").strip()

    with open("subfinder", "r") as f:
        code = f.read()

    code = code.replace('"domain_goes_here"', repr(domain))
    return _create_tool_task(f"subfinder_{domain}", code, 50)


# ─── Intruder ─────────────────────────────────────────────────────────────────

@app.route("/intruder")
def intruder():
    if "username" not in session:
        return redirect(url_for("signin"))
    return render_template("intruder.html")


# ─── Intruder proxy ───────────────────────────────────────────────────────────

@app.route("/intruder-proxy", methods=["POST"])
def intruder_proxy():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401

    data = request.get_json()
    url             = data.get("url", "").strip()
    method          = data.get("method", "GET").upper()
    headers         = data.get("headers", {})
    body            = data.get("body", "")
    follow_redirects = data.get("follow_redirects", True)

    if not url:
        return json.dumps({"error": "No URL provided"}), 400

    # Strip hop-by-hop headers that requests lib handles itself
    skip = {'host', 'content-length', 'connection', 'transfer-encoding', 'te'}
    clean_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

    try:
        resp = req_lib.request(
            method,
            url,
            headers=clean_headers,
            data=body.encode() if body else None,
            allow_redirects=follow_redirects,
            timeout=15,
            verify=False,  # allow self-signed certs
        )
        # resp.text auto-decompresses gzip/deflate — strip encoding headers
        # so the client doesn't try to decompress plain text again
        skip_resp = {'content-encoding', 'content-length', 'transfer-encoding'}
        raw_headers = "\r\n".join(
            f"{k}: {v}" for k, v in resp.headers.items()
            if k.lower() not in skip_resp
        )
        body_text = resp.text
        raw = (f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
               f"{raw_headers}\r\nContent-Length: {len(body_text.encode())}\r\n\r\n"
               f"{body_text}")
        return json.dumps({
            "status":       resp.status_code,
            "body":         body_text,
            "raw":          raw,
            "content_type": resp.headers.get("Content-Type", ""),
        })
    except RequestException as e:
        return json.dumps({
            "status": 0,
            "body":   f"[Error: {e}]",
            "raw":    f"[Error: {e}]",
        })


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
    # debug=False in production; use threaded=True for concurrent requests
    app.run(debug=False, threaded=True, host="127.0.0.1", port=5000)
