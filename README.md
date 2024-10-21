# Flask IT Ticket Management System

A simple Flask-based ticket management system where users can create, update, and close tickets. The system also includes email notifications and role-based access (admin and regular users).

## Features

- User authentication (admin and regular users)
- Ticket creation, updating, and closing
- Email notifications for ticket status changes
- Archived tickets page for closed tickets
- Simple role management (staff and regular users)

## Technologies

- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-Mail
- MySQL (PyMySQL)
- Python-dotenv for environment variable management

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/flask-ticket-system.git
    cd flask-ticket-system
    ```

2. Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate   # On Windows: venv\Scripts\activate
    ```

3. Install the required dependencies:
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-Login Flask-Mail python-dotenv PyMySQL
    ```

4. Set up environment variables by creating a `.env` file in the root directory:
    ```bash
    SECRET_KEY=your_secret_key
    DATABASE_URL=mysql://username:password@localhost/dbname
    MAIL_SERVER=smtp.gmail.com
    MAIL_PORT=587
    MAIL_USE_TLS=True
    MAIL_USERNAME=your_email@gmail.com
    MAIL_PASSWORD=your_email_password
    ```

## Database Setup

To set up the database, simply run the application. The database tables will be created automatically if they do not exist:

```bash
python app.py
