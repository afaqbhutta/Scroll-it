from flask import Flask, render_template, request, redirect, session, flash
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import urllib
import os
from datetime import timedelta

app = Flask(__name__)

# Better secret key management
.secret_key = os.environ.get('SECRET_KEY', '')app

# Session config
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
Session(app)

# Azure SQL connection
server = 'scrollitdb.database.windows.net'
database = 'scrollitDB'
username = 'sohaibadmin'
password = 'Parzival001.'
driver = '{ODBC Driver 17 for SQL Server}'

# Add timeout parameters
params = urllib.parse.quote_plus(
    f'DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password};'
    f'Connection Timeout=30;Command Timeout=30;Encrypt=yes;TrustServerCertificate=no;'
)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mssql+pyodbc:///?odbc_connect={params}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    IsCreator = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        try:
            user = User.query.get(session['user_id'])
            if user:
                return f"Welcome back, {user.username}! <a href='/logout'>Logout</a>"
            else:
                session.clear()
                return redirect('/login')
        except Exception as e:
            print(f"Database error: {e}")
            session.clear()
            return redirect('/login')
    return "Welcome! Please <a href='/login'>login</a> or <a href='/register'>register</a>."


@app.route('/register', methods=['GET', 'POST'])
def register():
    print(f"Request method: {request.method}")  # Debug
    if request.method == 'POST':

        #debugging 
        print("Form data received:")  # Debug
        print(f"Username: {request.form.get('username')}")
        print(f"Email: {request.form.get('email')}")
        print(f"Password: {request.form.get('password')}")
        print(f"UserType: {request.form.get('userType')}")


        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        user_type = request.form.get('userType')  # 'creator' or 'consumer'

        # Validation
        if not username or not email or not password or not confirm_password or not user_type:
            flash("All fields are required", "error")
            return render_template('register.html')

        # Email validation (basic)
        if '@' not in email or '.' not in email:
            flash("Please enter a valid email address", "error")
            return render_template('register.html')

        if user_type not in ['creator', 'consumer']:
            flash("Please select a valid user type", "error")
            return render_template('register.html')

        try:
            # Check if username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash("Username already taken", "error")
                return render_template('register.html')

            # Check if email already exists
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash("Email already registered", "error")
                return render_template('register.html')

            # Convert user_type to bit (0 for consumer, 1 for creator)
            is_creator = 1 if user_type == 'creator' else 0

            # Store hashed password
            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username, 
                email=email, 
                password=hashed_password,
                IsCreator=is_creator  # Assuming your User model has is_creator field
            )
            db.session.add(new_user)
            db.session.commit()

            flash("Registration successful! Please login.", "success")
            return redirect('/login')
        # in case the database is not connected or is not working
        except Exception as e:
            db.session.rollback()
            print(f"Database error: {e}")
            flash("Registration failed. Please try again.", "error")
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.clear()
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Please enter both username and password", "error")
            return render_template('login.html')

        try:
            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['email'] = user.email
                session['IsCreator'] = user.IsCreator  # Store user type in session
                
                flash(f"Welcome back, {user.username}!", "success")
                
                # Route based on user type
                if user.IsCreator == 1:  # Creator
                    return redirect('/creator')
                else:  # Consumer
                    return redirect('/consumer')
            else:
                flash("Invalid username or password", "error")
                return render_template('login.html')
        
        #exception for the database connection
        except Exception as e:
            print(f"Database error: {e}")
            flash("Login failed. Please try again.", "error")
            return render_template('login.html')

    return render_template('login.html')

# Route for creator dashboard
@app.route('/creator')
def creator():
    # Check if user is logged in and is a creator
    if 'user_id' not in session:
        flash("Please log in first", "error")
        return redirect('/login')
    
    if session.get('IsCreator') != 1:
        flash("Access denied. Creator account required.", "error")
        return redirect('/consumer')
    
    return render_template('creator.html')

# Route for consumer dashboard
@app.route('/consumer')
def consumer():
    # Check if user is logged in
    if 'user_id' not in session:
        flash("Please log in first", "error")
        return redirect('/login')
    
    return render_template('consumer.html')

# Optional: Route to switch between creator and consumer view (if user has both permissions)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first", "error")
        return redirect('/login')
    
    # Route based on user type
    if session.get('is_creator') == 1:
        return redirect('/creator')
    else:
        return redirect('/consumer')


#logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully", "info")
    return redirect('/')

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return "Internal server error", 500



if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully!")
        except Exception as e:
            print(f"Error creating tables: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)