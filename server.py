from flask import Flask, render_template, request, redirect, url_for, session
import csv
import os
import subprocess
import psutil
import json
import time
import threading
import signal

app = Flask(__name__)
threads = []
thread_dict={}
count=0
app.secret_key = "your_secret_key"

class MyThread(threading.Thread):
    def __init__(self, task_id,code):
        super(MyThread, self).__init__()
        self.task_id = task_id
        self.stop_event = threading.Event()
        self.code = code
        

    # def __init__(self, name,tasks,task):
    #     super(MyThread, self).__init__()
    #     self.tasks = tasks
    #     self.task = task
    #     self.name = name
    #     self.task_id= name
    #     self._stop_event = threading.Event()
    #     self._pause_event = threading.Event()
    #     self._pause_event.set()
    
    def run(self):
        code_path = f'code_{self.task_id}.py'
        cmd = "python "+str(code_path)
        print(cmd)
        try:
            exec(self.code,{'stop_event': self.stop_event})
        except:
            pass
        print("trying to terminate")

    # def run(self):
    #     try:
    #         subprocess.run(["python", self.name], check=True)
    #         self.task['status'] = 'Stopped'
    #         save_tasks(self.tasks)
    #     except subprocess.CalledProcessError:
    #         self.task['status'] = 'Stopped'
    #         save_tasks(self.tasks)

    def getpid(self):
        pid = os.getpid()
        return pid
            
    def stop(self):
        print("stopping thread")
        self.stop_event.set()

    # def stop(self):
    #     self._stop_event.set()

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

# Function to load tasks from CSV
def load_tasks():
    tasks = []
    with open('tasks.csv', 'r', newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            tasks.append(row)
    return tasks

# Function to save tasks to CSV
def save_tasks(tasks):
    with open('tasks.csv', 'w', newline='') as file:
        fieldnames = ['id', 'name', 'status','pid', 'code','cpu_usage']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(tasks)

# Function to load code from Python file
def load_code(code_path):
    with open(code_path, 'r') as file:
        code = file.read()
    return code

# Sign in page
@app.route('/', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if username and password are correct
        if username == 'your_username' and password == 'your_password':
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('signin.html', error='Invalid username or password')
    return render_template('signin.html', error=None)

# Dashboard page
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        tasks = load_tasks()
        return render_template('dashboard.html', tasks=tasks)
    return redirect(url_for('signin'))

# Function to get CPU usage
def get_cpu_usage():
    cpu_percent = psutil.cpu_percent(interval=1)  # Get CPU usage percentage
    return {'cpu_usage': cpu_percent}

# Route to get CPU usage
@app.route('/cpu-usage')
def cpu_usage():
    cpu_usage_data = get_cpu_usage()
    return json.dumps(cpu_usage_data)

# Start task
@app.route('/start/<int:task_id>')
def start_task(task_id):
    # if 'username' in session:
    #         tasks = load_tasks()
    #         for task in tasks:
    #             if int(task['id']) == task_id:
    #                 task['status'] = 'Running'
    #                 save_tasks(tasks)
    #                 code_path = f'code_{task_id}.py'
    #                 code = task.get('code')
    #                 with open(code_path, 'w') as f:
    #                     f.write(code)
    #                     print(f"The file '{code_path}' has been created/updated.")
    #                 if os.path.isfile(code_path):
    #                     thread = MyThread(code_path, task, tasks)
    #                     thread.start()
    #                 else:
    #                     task['status'] = 'Stopped'
    #                     save_tasks(tasks)
    #                 break
    #         return redirect(url_for('dashboard'))
    # return redirect(url_for('signin'))
    tasks = load_tasks()
    for task in tasks:
        if int(task['id']) == task_id:
            task['status'] = 'Running'
            (tasks)
            code_path = f'code_{task_id}.py'
            code = task.get('code')
    thread = MyThread(task_id,code)
    thread.start()
    return "Task started"

# Stop task
@app.route('/stop/<int:task_id>')
def stop_task(task_id):
    for thread in threading.enumerate():
        print(thread.__class__.__name__)
        if isinstance(thread, MyThread) and thread.task_id == task_id:
            thread.stop()
            return f"Task {task_id} stopped"
    return f"Task {task_id} not found"

    # if 'username' in session:
    #     tasks = load_tasks()
    #     code_path = f"code_{task_id}"
    #     for task in tasks:
    #         if int(task['id']) == task_id:
    #             task['status'] = 'Stopped'
    #             for thread in threading.enumerate():
    #                 print(thread)
    #                 if isinstance(thread, MyThread) and thread.task_id == code_path:
    #                     thread.stop()
    #             save_tasks(tasks)
    #             break
    #     return redirect(url_for('dashboard'))
    # return redirect(url_for('signin'))


# Show code editor
@app.route('/edit/<int:task_id>')
def edit_task(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                code = task.get('code')  # Check if code_path exists
                return render_template('editor.html', task=task, code=code)              
    return redirect(url_for('dashboard'))

# Save code
@app.route('/save/<int:task_id>', methods=['POST'])
def save_code(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                code = request.form['code']
                task['code'] = code  # Update the 'code' field in the task dictionary
                with open('tasks.csv', 'w', newline='') as csvfile:
                    fieldnames = ['id', 'name', 'status','pid', 'code','cpu_usage']  # Adjust according to your CSV
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerow(task)  # Append the updated task to the CSV file
                break
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))

def update_cpu_usage():
    while True:
        tasks = load_tasks()
        for task in tasks:
            # Update CPU usage for each task
            cpu_usage = psutil.cpu_percent(interval=1)  # Get CPU usage percentage
            task['cpu_usage'] = cpu_usage
        save_tasks(tasks)
        time.sleep(1)  # Update every 1 second

if __name__ == '__main__':
    import threading
    update_cpu_thread = threading.Thread(target=update_cpu_usage)
    update_cpu_thread.daemon = True
    # update_cpu_thread.start()

    app.run(debug=True)