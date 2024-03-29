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
            exec(self.code,{'stop_event': self.stop_event,'task':self})
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
    
    def update_total_batch(self,total):
        tasks=load_tasks()
        for task in tasks:
            if int(task['id']) == self.task_id:
                task['total'] = total
                save_tasks(tasks)

    def change_speed(self,val):
        self.speed = val

    def load_progress(self):
        tasks=load_tasks()
        for task in tasks:
            if int(task['id']) == self.task_id:
                return task['progress']
            
    def save_progress(self,progress):
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == self.task_id:
                task['progress'] = progress
                save_tasks(tasks)
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
        fieldnames = ['id', 'name', 'status','progress','total','speed', 'code','cpu_usage']
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
        if username == 'yogesh' and password == 'password':
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
def add_task(task_name='New',code='',speed=1):
    if 'username' in session:
        if 'name' in request.form:
            task_name = request.form['name']
        tasks = load_tasks()
        task_ids = [int(task['id']) for task in tasks]
        new_task_id = max(task_ids) + 1 if task_ids else 1
        new_task = {
            'id': str(new_task_id),
            'name': task_name,
            'status': 'Stopped',
            'progress': 0,
            'total': 1,
            'speed': speed,
            'code': code,
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
        os.remove(f'file_{task_id}') if os.path.exists(f'file_{task_id}') else None
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('signin'))

@app.route('/restart/<int:task_id>', methods=['POST'])
def restart_task(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task["id"]) == task_id:
                task["progress"] = 0
                os.remove(f'file_{task_id}') if os.path.exists(f'file_{task_id}') else None
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
                for thread in threading.enumerate():
                    if isinstance(thread, MyThread) and thread.task_id == task_id:
                        thread.change_speed(task['speed'])
                save_tasks(tasks)
                break
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))

@app.route('/nmap', methods=['POST'])
def nmap():
    ip = request.form.get('ip')
    all_ports = request.form.get('all_ports')
    start_port = request.form.get('start_port')
    end_port = request.form.get('end_port')
    print("IP Address:", ip)
    if all_ports:
        with open("nmap", 'r') as file:
            file_content = file.read()
            replaced_content = file_content.replace("start_range", "0").replace("end_range", "65535").replace("ip_goes_here",ip)
            add_task(task_name="nmap_"+ip,code=replaced_content,speed=500)
    else:
        with open("nmap", 'r') as file:
            file_content = file.read()
            replaced_content = file_content.replace("start_range", start_port).replace("end_range", end_port).replace("ip_goes_here",ip)
            add_task(task_name="nmap_"+ip,code=replaced_content,speed=100)
    return "added nmap"

@app.route('/dirbuster', methods=['POST'])
def dirbuster():
    url = request.json.get('url')
    print(url)
    status_codes = request.json.get('excludedstatuscodes', [])
    #print(status_codes)
    with open("dirbuster", 'r') as file:
            file_content = file.read()
            replaced_content = file_content.replace("url_goes_here", url).replace("array_status_code",str(status_codes))
            add_task(task_name="dirbuster_"+url,code=replaced_content,speed=500)
    return "dirbuster added"

@app.route('/file_<task_id>')
def get_file(task_id):
    # Construct the filename based on the task ID
    filename = f"file_{task_id}"
    # Check if the file exists
    if os.path.exists(filename):
        with open(f'file_{task_id}', 'r') as f:
            return f.read()
    else:
        return "File not found", 404

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