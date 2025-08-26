from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import re  # For input validation with regex

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production!

# Database initialization function
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Create users table with a 'role' column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    # Create vault table to store user data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    # Create an admin user if it doesn't exist
    hashed_admin_pw = generate_password_hash('adminpass')
    cursor.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                   ('admin', hashed_admin_pw, 'admin'))
    # Create a regular user if it doesn't exist
    hashed_user_pw = generate_password_hash('userpass')
    cursor.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                   ('user', hashed_user_pw, 'user'))
    conn.commit()
    conn.close()

init_db()

# -------------------------------
# SECURITY: Helper Functions & Decorators
# -------------------------------

def login_required(f):
    """Decorator to ensure a user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to ensure the logged-in user is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'admin':
            flash('You do not have permission to view this page.', 'danger')
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    """Helper function to get a database connection."""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Returns dictionaries instead of tuples
    return conn

# -------------------------------
# Routes: Authentication
# -------------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'user'  # Default role for new registrations

        # INPUT VALIDATION: Check for empty fields
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))

        # INPUT VALICATION: Simple username validation (alphanumeric)
        if not re.match("^[a-zA-Z0-9_]+$", username):
            flash('Username can only contain letters, numbers, and underscores.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        
        try:
            # SQL INJECTION PREVENTION: Using parameterized query
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                           (username, hashed_password, role))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        
        # SQL INJECTION PREVENTION: Parameterized query prevents injection here.
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            # Authentication successful, set up user session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# -------------------------------
# Routes: Application (Protected)
# -------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    # SECURE QUERY: Parameterized query using user_id from session, not user input.
    items = conn.execute('SELECT * FROM vault WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    # The template will automatically escape the 'data' to prevent XSS.
    return render_template('dashboard.html', items=items)

@app.route('/add', methods=['POST'])
@login_required
def add_item():
    data = request.form['data']
    if not data:
        flash('Data cannot be empty.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    # SECURE QUERY: Parameterized query prevents SQL Injection.
    conn.execute('INSERT INTO vault (user_id, data) VALUES (?, ?)',
                 (session['user_id'], data))
    conn.commit()
    conn.close()
    flash('Item added successfully.', 'success')
    return redirect(url_for('dashboard'))

# -------------------------------
# Routes: Admin Section (RBAC Example)
# -------------------------------

@app.route('/admin/dashboard')
@login_required
@admin_required  # RBAC: This decorator ensures only admins can access this.
def admin_dashboard():
    conn = get_db_connection()
    # Admin can see all data from all users
    all_data = conn.execute('''
        SELECT vault.id, vault.data, users.username
        FROM vault
        JOIN users ON vault.user_id = users.id
    ''').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', all_data=all_data)

if __name__ == '__main__':
    app.run(debug=True)  # Set debug=False in production!
