"""Security-tool launcher routes for The Great Automation.

Each route reads a tool template file (nmap, dirbuster, httpx, subfinder),
substitutes the user's parameters into it, and registers it as a new task.
Exposed as a Flask Blueprint so the existing URLs (/nmap, /dirbuster, ...)
keep working unchanged.
"""
from flask import Blueprint, request, redirect, url_for, session

from storage import load_tasks, save_tasks

tools_bp = Blueprint("tools", __name__)


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


@tools_bp.route("/nmap", methods=["POST"])
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


@tools_bp.route("/dirbuster", methods=["POST"])
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


@tools_bp.route("/httpx", methods=["POST"])
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


@tools_bp.route("/subfinder", methods=["POST"])
def subfinder():
    if "username" not in session:
        return redirect(url_for("signin"))
    data = request.get_json()
    domain = data.get("domain", "").strip()

    with open("subfinder", "r") as f:
        code = f.read()

    code = code.replace('"domain_goes_here"', repr(domain))
    return _create_tool_task(f"subfinder_{domain}", code, 50)
