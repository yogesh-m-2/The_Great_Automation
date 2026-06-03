"""Data layer for The Great Automation.

Holds the CSV-backed task store and the in-memory runtime state used to avoid
CSV reads/writes on hot paths (progress updates, speed changes, status polls).
No Flask or proxy dependencies — pure persistence.
"""
import csv
import os
import threading

TASKS_FILE = "tasks.csv"
FIELDNAMES = ["id", "name", "status", "progress", "total", "speed", "code", "cpu_usage"]

# ─── In-memory runtime state ─────────────────────────────────────────────────
# Holds live data for running tasks so we avoid CSV reads/writes in hot paths.
# Structure: { task_id: { "progress": int, "total": int, "speed": int,
#                         "status": str, "semaphore": threading.Semaphore } }
_runtime = {}
_runtime_lock = threading.Lock()


def runtime_get(task_id, key, default=None):
    with _runtime_lock:
        return _runtime.get(task_id, {}).get(key, default)


def runtime_set(task_id, key, value):
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
