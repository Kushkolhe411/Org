from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("admin123")

# Initialize database
def init_db():
    conn = sqlite3.connect('events.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    day TEXT NOT NULL,
                    date TEXT NOT NULL,
                    description TEXT NOT NULL,
                    type TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    conn = sqlite3.connect('events.db')
    c = conn.cursor()
    c.execute("SELECT * FROM events")
    events = c.fetchall()
    conn.close()
    return render_template('index.html', events=events)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect('events.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username or Email already exists. Try again."
        finally:
            conn.close()

        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Admin login check
        if username == 'admin' and check_password_hash(generate_password_hash("password") , password):
            session['admin_logged_in'] = True
            return redirect(url_for('dashboard'))

        # User login check
        conn = sqlite3.connect('events.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return "Invalid credentials. Try again."

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    session.pop('user_logged_in', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    conn = sqlite3.connect('events.db')
    c = conn.cursor()
    c.execute("SELECT * FROM events")
    events = c.fetchall()
    conn.close()
    return render_template('dashboard.html', events=events)

@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        day = request.form['day']
        date = request.form['date']
        description = request.form['description']
        event_type = request.form['type']

        conn = sqlite3.connect('events.db')
        c = conn.cursor()
        c.execute("INSERT INTO events (title, day, date, description, type) VALUES (?, ?, ?, ?, ?)", 
                  (title, day, date, description, event_type))
        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))
    return render_template('create_event.html')

@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
def edit_event(event_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    conn = sqlite3.connect('events.db')
    c = conn.cursor()

    # Fetch the existing event data for editing
    c.execute("SELECT * FROM events WHERE id=?", (event_id,))
    event = c.fetchone()

    if not event:
        return "Event not found."

    if request.method == 'POST':
        # Update the event with new data
        title = request.form['title']
        day = request.form['day']
        date = request.form['date']
        description = request.form['description']
        event_type = request.form['type']

        c.execute('''UPDATE events 
                     SET title=?, day=?, date=?, description=?, type=? 
                     WHERE id=?''', 
                  (title, day, date, description, event_type, event_id))
        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('edit_event.html', event=event)

@app.route('/delete_event/<int:event_id>', methods=['GET', 'POST'])
def delete_event(event_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    conn = sqlite3.connect('events.db')
    c = conn.cursor()

    # Delete the event with the given event_id
    c.execute("DELETE FROM events WHERE id=?", (event_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/register_event/<int:event_id>')
def register_event(event_id):
    if not session.get('user_logged_in'):
        return redirect(url_for('login'))

    conn = sqlite3.connect('events.db')
    c = conn.cursor()
    c.execute("SELECT * FROM events WHERE id=?", (event_id,))
    event = c.fetchone()
    conn.close()

    # Logic for event registration can be added here

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
