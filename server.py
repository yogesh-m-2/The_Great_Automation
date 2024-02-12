from flask import Flask, render_template, request, redirect, url_for, session
import csv
import os
import subprocess
import psutil
import json
import time

app = Flask(__name__)
app.secret_key = "your_secret_key"

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
        fieldnames = ['id', 'name', 'status', 'code_path']
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
                task['status'] = 'Running'
                save_tasks(tasks)
                code_path = task.get('code_path')
                if code_path and os.path.isfile(code_path):
                    # Execute Python code associated with the task
                    try:
                        subprocess.run(["python", code_path], check=True)
                    except subprocess.CalledProcessError:
                        task['status'] = 'Stopped'
                        save_tasks(tasks)
                else:
                    task['status'] = 'Stopped'
                    save_tasks(tasks)
                break
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))

# Stop task
@app.route('/stop/<int:task_id>')
def stop_task(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                task['status'] = 'Stopped'
                save_tasks(tasks)
                break
        return redirect(url_for('dashboard'))
    return redirect(url_for('signin'))


# Show code editor
@app.route('/edit/<int:task_id>')
def edit_task(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                code_path = task.get('code_path')  # Check if code_path exists
                if code_path and os.path.isfile(code_path):  # Check if code_path is valid
                    code = load_code(code_path)
                    return render_template('editor.html', task=task, code=code)
                else:
                    return render_template('editor.html', task=task)
    return redirect(url_for('dashboard'))

# Save code
@app.route('/save/<int:task_id>', methods=['POST'])
def save_code(task_id):
    if 'username' in session:
        tasks = load_tasks()
        for task in tasks:
            if int(task['id']) == task_id:
                code = request.form['code']
                code_path = task['code_path']
                with open(code_path, 'w') as file:
                    file.write(code)
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
    update_cpu_thread.start()

    app.run(debug=True)
