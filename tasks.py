"""Task execution thread for The Great Automation.

MyThread runs user-supplied code (via exec) in a background daemon thread with
speed-controlled concurrency backed by a semaphore. The methods below the
divider are the API exposed to that exec'd code as `task.*`.
"""
import threading

import storage
from storage import runtime_get, runtime_set, get_task, update_task_fields


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
        with storage._runtime_lock:
            storage._runtime[task_id] = {
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
            runtime_set(self.task_id, "status", final_status)
            # Persist final state to CSV
            progress = runtime_get(self.task_id, "progress", 0)
            total = runtime_get(self.task_id, "total", 1)
            update_task_fields(self.task_id, status=final_status,
                               progress=progress, total=total)

    # ── methods callable from exec'd code ────────────────────────────────────

    def get_speed(self):
        """Return current speed from in-memory state — no CSV read."""
        return str(runtime_get(self.task_id, "speed", 1))

    def change_speed(self, new_speed):
        new_speed = max(1, int(new_speed))
        with storage._runtime_lock:
            state = storage._runtime.get(self.task_id, {})
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
        runtime_set(self.task_id, "progress", progress)
        # Persist every 5 saves to reduce CSV I/O
        with storage._runtime_lock:
            state = storage._runtime.get(self.task_id, {})
            count = state.get("_save_counter", 0) + 1
            state["_save_counter"] = count
            if count % 5 == 0:
                update_task_fields(self.task_id, progress=progress)

    def update_total_batch(self, total):
        runtime_set(self.task_id, "total", total)
        update_task_fields(self.task_id, total=total)

    def acquire_slot(self):
        """Worker threads call this instead of the busy-wait loop."""
        sem = runtime_get(self.task_id, "semaphore")
        if sem:
            sem.acquire()

    def release_slot(self):
        """Worker threads call this when done."""
        sem = runtime_get(self.task_id, "semaphore")
        if sem:
            sem.release()

    def stop(self):
        self.stop_event.set()
