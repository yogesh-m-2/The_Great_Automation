from flask import Flask, render_template, request, redirect, url_for, session
import csv
import os
import subprocess
import psutil
import json
import time
import threading

app = Flask(__name__)
app.secret_key = "your_secret_key"

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
            subprocess.run(["python", self.name], check=True)
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

class AppController:
    threads = []
    count = 0
    threads_dict = {}

    @staticmethod
    def load_tasks():
        tasks = []
        with open('tasks.csv', 'r', newline='') as file:
            reader = csv.DictReader(file)
            for row in reader:
                tasks.append(row)
        return tasks

    @staticmethod
    def save_tasks(tasks):
        with open('tasks.csv', 'w', newline='') as file:
            fieldnames = ['id', 'name', 'status', 'code', 'cpu_usage']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(tasks)

    @staticmethod
    def load_code(code_path):
        with open(code_path, 'r') as file:
            code = file.read()
        return code

    @staticmethod
    @app.route('/', methods=['GET', 'POST'])
    def signin():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            if username == 'your_username' and password == 'your_password':
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                return render_template('signin.html', error='Invalid username or password')
        return render_template('signin.html', error=None)

    @staticmethod
    @app.route('/dashboard')
    def dashboard():
        if 'username' in session:
            tasks = AppController.load_tasks()
            return render_template('dashboard.html', tasks=tasks)
        return redirect(url_for('signin'))

    @staticmethod
    def get_cpu_usage():
        cpu_percent = psutil.cpu_percent(interval=1)
        return {'cpu_usage': cpu_percent}

    @staticmethod
    @app.route('/cpu-usage')
    def cpu_usage():
        cpu_usage_data = AppController.get_cpu_usage()
        return json.dumps(cpu_usage_data)

    @staticmethod
    @app.route('/start/<int:task_id>')
    def start_task(task_id):
        if 'username' in session:
            tasks = AppController.load_tasks()
            for task in tasks:
                if int(task['id']) == task_id:
                    task['status'] = 'Running'
                    AppController.save_tasks(tasks)
                    code_path = f'code_{task_id}.py'
                    code = task.get('code')
                    with open(code_path, 'w') as f:
                        f.write(code)
                        print(f"The file '{code_path}' has been created/updated.")
                    if os.path.isfile(code_path):
                        thread = MyThread(code_path, task, tasks)
                        thread.start()
                        AppController.threads.append(thread)
                        AppController.threads_dict[code_path] = AppController.count
                        AppController.count += 1
                    else:
                        task['status'] = 'Stopped'
                        AppController.save_tasks(tasks)
                    break
            return redirect(url_for('dashboard'))
        return redirect(url_for('signin'))

    @staticmethod
    @app.route('/stop/<int:task_id>')
    def stop_task(task_id):
        if 'username' in session:
            tasks = AppController.load_tasks()
            code_path = f"code_{task_id}.py"
            for task in tasks:
                if int(task['id']) == task_id:
                    task['status'] = 'Stopped'
                    print(AppController.threads,AppController.threads_dict)
                    AppController.threads[AppController.threads_dict[code_path]].stop()
                    AppController.save_tasks(tasks)
                    break
            return redirect(url_for('dashboard'))
        return redirect(url_for('signin'))

    @staticmethod
    @app.route('/edit/<int:task_id>')
    def edit_task(task_id):
        if 'username' in session:
            tasks = AppController.load_tasks()
            for task in tasks:
                if int(task['id']) == task_id:
                    code = task.get('code')
                    return render_template('editor.html', task=task, code=code)
        return redirect(url_for('dashboard'))

    @staticmethod
    @app.route('/save/<int:task_id>', methods=['POST'])
    def save_code(task_id):
        if 'username' in session:
            tasks = AppController.load_tasks()
            for task in tasks:
                if int(task['id']) == task_id:
                    code = request.form['code']
                    task['code'] = code
                    with open('tasks.csv', 'w', newline='') as csvfile:
                        fieldnames = ['id', 'name', 'status', 'code', 'cpu_usage']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(tasks)
                    break
            return redirect(url_for('dashboard'))
        return redirect(url_for('signin'))

    @staticmethod
    def update_cpu_usage():
        while True:
            tasks = AppController.load_tasks()
            for task in tasks:
                cpu_usage = psutil.cpu_percent(interval=1)
                task['cpu_usage'] = cpu_usage
            AppController.save_tasks(tasks)
            time.sleep(1)

if __name__ == '__main__':
    # update_cpu_thread = threading.Thread(target=AppController.update_cpu_usage)
    # update_cpu_thread.daemon = True
    # update_cpu_thread.start()
    app.run(debug=True)
