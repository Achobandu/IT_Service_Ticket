import pymysql
pymysql.install_as_MySQLdb()

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from flask_mail import Mail, Message
import os

from dotenv import load_dotenv

# import env variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_staff = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    priority = db.Column(db.String(20), default='Medium')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    closed_at = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def send_email(subject, recipient, body):
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[recipient])
    msg.body = body
    mail.send(msg)

@app.route('/')
@login_required
def index():
    if current_user.is_staff:
        tickets = Ticket.query.filter_by(status= 'Open').all()
    else:
        tickets = Ticket.query.filter_by(user_id=current_user.id, status='Open').all()
    return render_template('index.html', tickets=tickets)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/ticket/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if request.method == 'POST':
        new_ticket = Ticket(
            title=request.form['title'],
            description=request.form['description'],
            priority=request.form['priority'],
            user_id=current_user.id
        )
        db.session.add(new_ticket)
        db.session.commit()
        send_email('New Ticket Created', current_user.email, f'Your ticket "{new_ticket.title}" has been created.')
        flash('Ticket created successfully')
        return redirect(url_for('index'))
    return render_template('new_ticket.html')

@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_staff and ticket.user_id != current_user.id:
        flash('You do not have permission to view this ticket')
        return redirect(url_for('index'))
    return render_template('view_ticket.html', ticket=ticket)

@app.route('/ticket/<int:ticket_id>/update', methods=['GET', 'POST'])
@login_required
def update_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_staff and ticket.user_id != current_user.id:
        flash('You do not have permission to update this ticket')
        return redirect(url_for('index'))
    if request.method == 'POST':
        ticket.title = request.form['title']
        ticket.description = request.form['description']
        ticket.status = request.form['status']
        ticket.priority = request.form['priority']

        if ticket.status == 'Closed':
            ticket.closed_at = datetime.now(timezone.utc)
        else:
            ticket.closed_at = None
        if current_user.is_staff:
            assigned_to = User.query.filter_by(username=request.form['assigned_to']).first()
            if assigned_to:
                ticket.assigned_to = assigned_to.id

        db.session.commit()
        send_email('Ticket Updated', current_user.email, f'Your ticket "{ticket.title}" has been updated.')
        flash('Ticket updated successfully')
        return redirect(url_for('view_ticket', ticket_id=ticket.id))

    staff = User.query.filter_by(is_staff=True).all()
    return render_template('update_ticket.html', ticket=ticket, staff=staff)


@app.route('/create_user', methods=['GET', 'POST'])
@login_required  # Ensure only logged-in users (admins) can create new users
def create_user():
    if not current_user.is_staff:  # Check if the current user is an admin/staff
        flash('You do not have permission to create users')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_staff = request.form.get('is_staff') == 'on'  # Checkbox for staff privileges

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists')
            return redirect(url_for('create_user'))

        new_user = User(username=username, email=email, is_staff=is_staff)
        new_user.set_password(password)  # Hash the password

        db.session.add(new_user)
        db.session.commit()

        flash('User created successfully')
        return redirect(url_for('index'))

    return render_template('create_user.html')  # Create a form for user creation

@app.route('/archive')
@login_required
def archive():
    if current_user.is_staff:
        tickets = Ticket.query.filter(Ticket.closed_at.isnot(None)).all()
    else:
        tickets = Ticket.query.filter(user_id=current_user.id).filter(Ticket.closed_at.isnot(None)).all()
    return render_template('archive.html', tickets=tickets)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', email='admin@example.com', is_staff=True)
            admin_user.set_password('admin_password')
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True)
