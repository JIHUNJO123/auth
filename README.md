🛡️ SafeVault - Capstone Project
SafeVault is a secure web application developed with the Flask framework, created as a capstone project to demonstrate essential web security practices.

This project clearly showcases the implementation of input validation, SQL injection prevention, secure user authentication, and Role-Based Access Control (RBAC).

🚀 Core Features
🔐 Secure User Authentication: Provides secure login/logout functionality with session management.

🛡️ Password Encryption: Protects user passwords with a strong hashing algorithm using the Werkzeug library.

📝 Input Validation: Prevents invalid data by validating usernames and all other form submissions.

💉 SQL Injection Prevention: Secures the database from SQL injection attacks by exclusively using parameterized queries.

⚔️ XSS Prevention: Mitigates Cross-Site Scripting (XSS) attacks through the auto-escaping feature of Jinja2 templates.

👑 Role-Based Access Control (RBAC): Restricts access to admin-only pages by implementing an @admin_required decorator.

🗂️ Database: Uses the simple and convenient SQLite.

🛠️ Installation and Setup
Clone the Project Repository

Bash

git clone <your-github-repo-url>
cd safevault-capstone
Create a Virtual Environment and Install Dependencies

Bash

# Create a virtual environment
python -m venv venv

# Activate the virtual environment (For Windows, use: venv\Scripts\activate)
source venv/bin/activate

# Install the required packages
pip install -r requirements.txt
Run the Application

Bash

python app.py
After running, you can access the application by navigating to http://127.0.0.1:5000 in your web browser.

🧪 Test Credentials
The following two accounts have been pre-configured to allow for testing the different roles.

Administrator (Admin)

Username: admin

Password: adminpass

Standard User (User)

Username: user

Password: userpass

You can also register new users through the sign-up page. Newly registered users are assigned the 'user' role by default.

✨ AI-Assisted Development (How Copilot Assisted)
This project was developed with the assistance of GitHub Copilot. Copilot was utilized to generate secure code patterns, such as parameterized SQL queries, password hashing functions, and the structure for the RBAC decorator.

It also helped to quickly write boilerplate code for Flask routes and HTML templates, which allowed for a greater focus on implementing and refining the core security features.
