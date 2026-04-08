from flask import Flask, render_template, request, redirect, url_for, session, json
import csv
import os
import threading
import time
import psutil

app = Flask(__name__)
app.secret_key = "your_secret_key"

TASKS_FILE = "tasks.csv"
FIELDNAMES = ["id", "name", "status", "progress", "total", "speed", "code", "cpu_usage"]


# ─── CSV helpers ────────────────────────────────────────────────────────────────

def load_tasks():
    tasks = []
    if not os.path.exists(TASKS_FILE):
        return tasks
    with open(TASKS_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tasks.append(row)
    return tasks


def save_tasks(tasks):
    with open(TASKS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(tasks)


def get_task(task_id):
    for t in load_tasks():
        if int(t["id"]) == task_id:
            return t
    return None


# ─── Thread class ────────────────────────────────────────────────────────────────

class MyThread(threading.Thread):
    def __init__(self, task_id, code, speed):
        super().__init__()
        self.task_id = task_id
        self.stop_event = threading.Event()
        self.code = code
        self.speed = speed
        self.daemon = True

    def run(self):
        try:
            exec(self.code, {"stop_event": self.stop_event, "task": self})
        except Exception as e:
            print(f"[Task {self.task_id}] Error: {e}")
        finally:
            tasks = load_tasks()
            for t in tasks:
                if int(t["id"]) == self.task_id:
                    t["status"] = "Stopped"
            save_tasks(tasks)

    # ── methods callable from exec'd code ───────────────────────────────────────

    def get_speed(self):
        return self.speed

    def change_speed(self, val):
        self.speed = val

    def load_progress(self):
        t = get_task(self.task_id)
        return t["progress"] if t else "0"

    def save_progress(self, progress):
        tasks = load_tasks()
        for t in tasks:
            if int(t["id"]) == self.task_id:
                t["progress"] = progress
        save_tasks(tasks)

    def update_total_batch(self, total):
        tasks = load_tasks()
        for t in tasks:
            if int(t["id"]) == self.task_id:
                t["total"] = total
        save_tasks(tasks)

    def stop(self):
        self.stop_event.set()


# ─── Auth ────────────────────────────────────────────────────────────────────────

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


# ─── Dashboard ───────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("signin"))
    tasks = load_tasks()
    return render_template("dashboard.html", tasks=tasks)


# ─── Task CRUD ───────────────────────────────────────────────────────────────────

@app.route("/add-task", methods=["POST"])
def add_task():
    if "username" not in session:
        return redirect(url_for("signin"))

    # Accept both form-data and JSON (used by tool routes)
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
    # Stop thread if running
    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
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
    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            t["progress"] = 0
    save_tasks(tasks)
    outfile = f"file_{task_id}"
    if os.path.exists(outfile):
        os.remove(outfile)
    return redirect(url_for("dashboard"))


# ─── Task control ────────────────────────────────────────────────────────────────

@app.route("/start/<int:task_id>")
def start_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            if t["status"] == "Running":
                return "<script>alert('Task is already running'); window.location.href='/dashboard'</script>"
            t["status"] = "Running"
            thread = MyThread(task_id, t["code"], t["speed"])
            thread.start()
            save_tasks(tasks)
            return redirect(url_for("dashboard"))

    return redirect(url_for("dashboard"))


@app.route("/stop/<int:task_id>")
def stop_task(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))

    for thread in threading.enumerate():
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
            tasks = load_tasks()
            for t in tasks:
                if int(t["id"]) == task_id:
                    t["status"] = "Stopped"
            save_tasks(tasks)
            return redirect(url_for("dashboard"))

    return "<script>alert('Task is not running'); window.location.href='/dashboard'</script>"


# ─── Speed control ───────────────────────────────────────────────────────────────

@app.route("/increase-speed/<int:task_id>")
def increase_speed(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            t["speed"] = int(t["speed"]) + 1
            for thread in threading.enumerate():
                if isinstance(thread, MyThread) and thread.task_id == task_id:
                    thread.change_speed(t["speed"])
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/decrease-speed/<int:task_id>")
def decrease_speed(task_id):
    if "username" not in session:
        return redirect(url_for("signin"))
    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            t["speed"] = max(1, int(t["speed"]) - 1)
            for thread in threading.enumerate():
                if isinstance(thread, MyThread) and thread.task_id == task_id:
                    thread.change_speed(t["speed"])
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


# ─── Code editor ─────────────────────────────────────────────────────────────────

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
    tasks = load_tasks()
    for t in tasks:
        if int(t["id"]) == task_id:
            t["code"] = request.form["code"]
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


# ─── Output file viewer ──────────────────────────────────────────────────────────

@app.route("/file_<task_id>")
def get_file(task_id):
    filename = f"file_{task_id}"
    if os.path.exists(filename):
        with open(filename, "r", errors="ignore") as f:
            return f.read(), 200, {"Content-Type": "text/plain"}
    return "No output yet.", 404


# ─── CPU usage (AJAX) ────────────────────────────────────────────────────────────

@app.route("/cpu-usage")
def cpu_usage():
    return json.dumps({"cpu_usage": psutil.cpu_percent(interval=0.5)})


# ─── Task status (AJAX polling) ──────────────────────────────────────────────────

@app.route("/task-status")
def task_status():
    tasks = load_tasks()
    result = []
    for t in tasks:
        total = max(int(t.get("total", 1)), 1)
        progress = int(t.get("progress", 0))
        pct = round((progress / total) * 100, 1)
        result.append({
            "id": t["id"],
            "status": t["status"],
            "progress": pct,
            "speed": t["speed"],
        })
    return json.dumps(result)


# ─── Tool routes ─────────────────────────────────────────────────────────────────

@app.route("/nmap", methods=["POST"])
def nmap():
    ip = request.form.get("ip")
    all_ports = request.form.get("all_ports")
    start_port = request.form.get("start_port", "0")
    end_port = request.form.get("end_port", "1024")

    with open("nmap", "r") as f:
        code = f.read()

    if all_ports:
        code = code.replace("start_range", "0").replace("end_range", "65535")
        speed = 500
    else:
        code = code.replace("start_range", start_port).replace("end_range", end_port)
        speed = 100

    code = code.replace("ip_goes_here", ip)

    tasks = load_tasks()
    ids = [int(t["id"]) for t in tasks]
    new_id = max(ids) + 1 if ids else 1
    tasks.append({
        "id": str(new_id), "name": f"nmap_{ip}", "status": "Stopped",
        "progress": 0, "total": 1, "speed": speed, "code": code, "cpu_usage": ""
    })
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/dirbuster", methods=["POST"])
def dirbuster():
    data = request.get_json()
    url = data.get("url")
    status_codes = data.get("excludedstatuscodes", [])

    with open("dirbuster", "r") as f:
        code = f.read()

    code = code.replace("url_goes_here", url).replace("array_status_code", str(status_codes))

    tasks = load_tasks()
    ids = [int(t["id"]) for t in tasks]
    new_id = max(ids) + 1 if ids else 1
    tasks.append({
        "id": str(new_id), "name": f"dirbuster_{url}", "status": "Stopped",
        "progress": 0, "total": 1, "speed": 500, "code": code, "cpu_usage": ""
    })
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/httpx", methods=["POST"])
def httpx():
    data = request.get_json()
    targets = data.get("targets", "")  # newline-separated list

    with open("httpx", "r") as f:
        code = f.read()

    code = code.replace("targets_goes_here", targets)

    tasks = load_tasks()
    ids = [int(t["id"]) for t in tasks]
    new_id = max(ids) + 1 if ids else 1
    tasks.append({
        "id": str(new_id), "name": "httpx_probe", "status": "Stopped",
        "progress": 0, "total": 1, "speed": 100, "code": code, "cpu_usage": ""
    })
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


@app.route("/subfinder", methods=["POST"])
def subfinder():
    data = request.get_json()
    domain = data.get("domain")

    with open("subfinder", "r") as f:
        code = f.read()

    code = code.replace("domain_goes_here", domain)

    tasks = load_tasks()
    ids = [int(t["id"]) for t in tasks]
    new_id = max(ids) + 1 if ids else 1
    tasks.append({
        "id": str(new_id), "name": f"subfinder_{domain}", "status": "Stopped",
        "progress": 0, "total": 1, "speed": 50, "code": code, "cpu_usage": ""
    })
    save_tasks(tasks)
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    # Initialise CSV if missing
    if not os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
    app.run(debug=True, threaded=True)
