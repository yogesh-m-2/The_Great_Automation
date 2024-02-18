import threading
import subprocess
import time

threads = []


class AppController:
    @staticmethod
    def save_tasks(tasks):
        # Placeholder method for saving tasks
        print("Tasks saved.")

class MyThread(threading.Thread):
    def __init__(self, name, task, tasks):
        super().__init__()
        self.tasks = tasks
        self.task = task
        self.name = name
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()

    def run(self):
        try:
            while not self._stop_event.is_set():
                # Simulate some activity (printing)
                print(f"{self.name}: Running...")

            self.task['status'] = 'Stopped'
            AppController.save_tasks(self.tasks)
        except subprocess.CalledProcessError:
            self.task['status'] = 'Stopped'
            AppController.save_tasks(self.tasks)

    def stop(self):
        self._stop_event.set()

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

class ThreadManager:
    threads = []

    @classmethod
    def add_thread(cls, thread):
        cls.threads.append(thread)

    @classmethod
    def stop_thread(cls, thread_name):
        for thread in cls.threads:
            if thread.name == thread_name:
                thread.stop()
                break

def a():
    global threads
    tasks = [{'name': 'Task1', 'status': 'Running'}, {'name': 'Task2', 'status': 'Running'}]
    t1 = MyThread("Task1.py", tasks[0], tasks)
    threads.append(t1)
    print(threads)

def b():
    global threads
    print(threads)

if __name__ == "__main__":
    # tasks = [{'name': 'Task1', 'status': 'Running'}, {'name': 'Task2', 'status': 'Running'}]

    # thread1 = MyThread("Task1.py", tasks[0], tasks)
    # thread2 = MyThread("Task2.py", tasks[1], tasks)

    # ThreadManager.add_thread(thread1)
    # ThreadManager.add_thread(thread2)

    # thread1.start()
    # thread2.start()

    # time.sleep(5)

    # ThreadManager.stop_thread("Task2.py")  # Stop Task2.py

    # # Join threads
    # thread1.join()
    # thread2.join()

    # print("All threads have stopped.")

    a()
    b()
