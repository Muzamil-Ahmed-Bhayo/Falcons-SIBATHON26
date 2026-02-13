# SIBATHON26 - User Authentication System

A web application with login and signup functionality using Flask and SQLite database.

## Features

- User registration (signup)
- User authentication (login)
- Password hashing for security
- User profile page
- Session management
- Flash messages for user feedback

## Technologies Used

- Flask - Web framework
- SQLite - Database
- SQLAlchemy - ORM
- Flask-Login - User session management
- Werkzeug - Password hashing
- Bootstrap - Frontend styling

## Setup Instructions

1. Clone the repository
2. Install the required packages:
   ```
   pip install flask flask-sqlalchemy flask-login
   ```
3. Run the application:
   ```
   python App.py
   ```
4. Open your browser and navigate to `http://127.0.0.1:5000/`

## Project Structure

- `App.py` - Main application file with routes and database models
- `templates/` - HTML templates
  - `base.html` - Base template with navigation and layout
  - `index.html` - Home page
  - `login.html` - Login form
  - `signup.html` - Registration form
  - `profile.html` - User profile page
- `instance/` - Contains the SQLite database file (created automatically)
