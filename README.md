SafeVault - A Capstone Project
SafeVault is a secure web application built with Flask, designed to demonstrate essential security practices. The project showcases the implementation of input validation, SQL injection prevention, secure authentication, and Role-Based Access Control (RBAC).

Core Features
Secure Authentication: Manages user login, logout, and sessions securely.

Password Encryption: Utilizes Werkzeug's robust library for hashing and securing user passwords.

Input Validation: Enforces validation rules for usernames and all other form data.

SQL Injection Defense: Protects the database by using parameterized queries exclusively.

XSS Mitigation: Prevents Cross-Site Scripting attacks by automatically escaping user input in Jinja2 templates.

Role-Based Access Control (RBAC): Implements an @admin_required decorator to restrict access to sensitive areas.

Database: Employs SQLite for simplified database management.

Installation and Setup
Clone the project repository:

Bash

git clone <your-github-repo-url>
cd safevault-capstone
Create a virtual environment and install packages:

Bash

python -m venv venv
source venv/bin/activate  # For Windows: venv\Scripts\activate
pip install -r requirements.txt
Launch the application:

Bash

python app.py
The application will then be running at http://127.0.0.1:5000.

Sample Credentials
Administrator: username: admin, password: adminpass

Standard User: username: user, password: userpass

You can also register new accounts, which are assigned the 'user' role by default.

AI-Assisted Development
GitHub Copilot was utilized to accelerate development by generating secure code patterns for features like parameterized SQL queries, password hashing, and the RBAC decorator. It also helped scaffold boilerplate code for Flask routes and HTML templates, allowing for a greater focus on implementing and refining the core security features.
