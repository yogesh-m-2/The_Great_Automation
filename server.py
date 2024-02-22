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
    def __init__(self, task_id,code,speed):
        super(MyThread, self).__init__()
        self.task_id = task_id
        self.stop_event = threading.Event()
        self.code = code
        self.speed = speed
        
    
    def run(self):
        code_path = f'code_{self.task_id}.py'
        cmd = "python "+str(code_path)
        print(cmd)
        try:
            exec(self.code,{'stop_event': self.stop_event,'speed':self})
        except Exception as e:
            print(e)
            tasks=load_tasks()
            for task in tasks:
                if int(task['id']) == self.task_id:
                    task['status'] = 'Stopped'
                    save_tasks(tasks)
            pass
        print("trying to terminate")
            
        tasks=load_tasks()
        for task in tasks:
            if int(task['id']) == self.task_id:
                task['status'] = 'Stopped'
                save_tasks(tasks)
        print("trying to terminate")

    def get_speed(self):
        return self.speed

    def change_speed(self,val):
        self.speed = val
            
    def stop(self):
        print("stopping thread")
        self.stop_event.set()

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
        fieldnames = ['id', 'name', 'status','progress','speed', 'code','cpu_usage']
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
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                if task['status'] == 'Running':
                    return f"<script>alert('task is already running'); window.location.href='/dashboard'</script>"
                else:
                    task['status'] = 'Running'
                    code = task.get('code')
                    speed = task.get('speed')
                    thread = MyThread(task_id,code,speed)
                    thread.start()
                    save_tasks(tasks)
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))

# Stop task
@app.route('/stop/<int:task_id>')
def stop_task(task_id):
    if 'username' in session:
        for thread in threading.enumerate():
            if isinstance(thread, MyThread) and thread.task_id == task_id:
                thread.stop()
                tasks = load_tasks()
                for task in tasks:
                    if int(task['id']) == task_id:
                        task['status'] = 'Stopped'
                        save_tasks(tasks)
                return redirect(url_for('dashboard'))
        return f"<script>alert('task is not running'); window.location.href='/dashboard'</script>"
    return redirect(url_for('signin'))


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
                save_tasks(tasks)
                break
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))

@app.route('/add-task', methods=['POST'])
def add_task():
    if 'username' in session:
        task_name = request.form['name']
        tasks = load_tasks()
        task_ids = [int(task['id']) for task in tasks]
        new_task_id = max(task_ids) + 1 if task_ids else 1
        new_task = {
            'id': str(new_task_id),
            'name': task_name,
            'status': 'Stopped',
            'progress': '',
            'speed': 1,
            'code': '',
            'cpu_usage': ''
        }
        tasks.append(new_task)
        save_tasks(tasks)
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))

# Delete task
@app.route('/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'username' in session:
        tasks = load_tasks()
        tasks = [task for task in tasks if int(task['id']) != task_id]
        save_tasks(tasks)
        
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('signin'))

@app.route('/increase-speed/<int:task_id>')
def increase_speed(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                task['speed'] = int(task['speed']) + 1
                for thread in threading.enumerate():
                    if isinstance(thread, MyThread) and thread.task_id == task_id:
                        thread.change_speed(task['speed'])
                save_tasks(tasks)
                break
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))

# Decrease speed
@app.route('/decrease-speed/<int:task_id>')
def decrease_speed(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                # Convert to integer and decrease speed, but ensure it's not below 1
                task['speed'] = max(int(task['speed']) - 1, 1)
                save_tasks(tasks)
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