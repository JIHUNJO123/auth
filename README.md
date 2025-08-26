# SafeVault - Capstone Project

A secure Flask web application demonstrating input validation, SQL injection prevention, authentication, and Role-Based Access Control (RBAC).

## Features

- **Secure User Authentication:** Login/Logout with session management.
- **Password Hashing:** Uses Werkzeug's secure password hashing.
- **Input Validation:** Validates usernames and form data.
- **SQL Injection Prevention:** Uses parameterized queries exclusively.
- **XSS Prevention:** User input is escaped in Jinja2 templates.
- **Role-Based Access Control (RBAC):** Implements an `@admin_required` decorator.
- **Database:** SQLite for simplicity.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-github-repo-url>
    cd safevault-capstone
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    python app.py
    ```
    The app will be available at `http://127.0.0.1:5000`.

## Test Logins

- **Admin User:** username: `admin`, password: `adminpass`
- **Regular User:** username: `user`, password: `userpass`

You can also register new users (who will have the 'user' role by default).

## How Copilot Assisted

Copilot was used to generate secure code patterns, such as parameterized SQL queries, password hashing functions, and the RBAC decorator structure. It also helped quickly generate boilerplate code for Flask routes and HTML templates, allowing a focus on implementing security features.
