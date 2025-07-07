from flask import Flask, render_template, request, redirect, session, flash
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import urllib
import os
from datetime import timedelta
from azure.storage.blob import BlobServiceClient
from werkzeug.utils import secure_filename
from uuid import uuid4
from dotenv import load_dotenv

# to fethc the secret keys from the .env
load_dotenv()


# Azure Blob Storage settings
AZURE_CONNECTION_STRING = os.environ['AZURE_BLOB_CONN_STRING']
AZURE_CONTAINER_NAME = 'videos'
blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
blob_container_client = blob_service_client.get_container_client(AZURE_CONTAINER_NAME)

app = Flask(__name__)

# secret key management
app.secret_key = os.environ['SECRET_KEY']

# Session config
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
Session(app)

# Azure SQL connection
server = 'scrollitdb.database.windows.net'
database = 'scrollitDB'
username = 'sohaibadmin'
password = os.environ['SQL_DB_PASSWORD']
driver = '{ODBC Driver 17 for SQL Server}'

# Add timeout parameters
params = urllib.parse.quote_plus(
    f'DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password};'
    f'Connection Timeout=30;Command Timeout=30;Encrypt=yes;TrustServerCertificate=no;'
)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mssql+pyodbc:///?odbc_connect={params}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# *** Models for the database entries ***
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    IsCreator = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Video(db.Model):
    __tablename__ = 'videos'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    publisher = db.Column(db.String(255), nullable=True)
    producer = db.Column(db.String(255), nullable=True)
    genre = db.Column(db.String(100), nullable=True)
    age_rating = db.Column(db.String(10), nullable=True)  # e.g., PG, 18, etc.
    description = db.Column(db.Text, nullable=True)
    blob_url = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    uploaded_at = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f'<Video {self.title}>'

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    #for the username that commented...
    user = db.relationship('User', backref='comments')

class Rating(db.Model):
    __tablename__ = 'ratings'
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False) 
    created_at = db.Column(db.DateTime, server_default=db.func.now())


# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        try:
            user = User.query.get(session['user_id'])
            if user:
                return redirect('/dashboard')
            else:
                session.clear()
                return redirect('/login')
        except Exception as e:
            print(f"Database error: {e}")
            session.clear()
            return redirect('/login')
    return render_template('register.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    print(f"Request method: {request.method}")  # Debug
    if request.method == 'POST':
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

@app.route('/creator', methods=['GET', 'POST'])
def creator():
    if 'user_id' not in session or session.get('IsCreator') != 1:
        flash("Access denied. Creator account required.", "error")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        publisher = request.form.get('publisher')
        producer = request.form.get('producer')
        genre = request.form.get('genre')
        age_rating = request.form.get('age_rating')
        file = request.files.get('video')

        if not file or not title:
            flash("Title and video file are required.", "error")
            return redirect('/creator')

        try:
            filename = secure_filename(file.filename)
            unique_name = f"{uuid4()}_{filename}"
            blob_client = blob_container_client.get_blob_client(unique_name)

            blob_client.upload_blob(file.stream, overwrite=True)

            blob_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{unique_name}"

            video = Video(
                title=title,
                description=description,
                publisher=publisher,
                producer=producer,
                genre=genre,
                age_rating=age_rating,
                blob_url=blob_url,
                uploaded_by=session['user_id']
            )
            db.session.add(video)
            db.session.commit()

            flash("Video uploaded successfully!", "success")
        except Exception as e:
            print(f"Upload error: {e}")
            db.session.rollback()
            flash("Video upload failed.", "error")

        return redirect('/creator')  # Redirect only after POST

    # GET: Render page with uploaded videos
    videos = Video.query.filter_by(uploaded_by=session['user_id']).order_by(Video.uploaded_at.desc()).all()
    return render_template('creator.html', videos=videos)


# Route for consumer dashboard
@app.route('/consumer', methods = ['GET', 'POST'])
def consumer():
    # Check if user is logged in
    if 'user_id' not in session:
        flash("Please log in first", "error")
        return redirect('/login')
    
    return redirect('/dashboard')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to view the dashboard", "error")
        return redirect('/login')

    # Handle POST: comment, rating or comment deletion
    if request.method == 'POST':
        try:
            # Delete comment
            delete_comment_id = request.form.get('delete_comment_id')
            if delete_comment_id:
                comment = Comment.query.get(int(delete_comment_id))
                if comment and comment.user_id == session['user_id']:
                    db.session.delete(comment)
                    db.session.commit()
                    flash("Comment deleted", "info")
                else:
                    flash("Unauthorized or comment not found", "error")
                return redirect('/dashboard')

            # Submit comment and/or rating
            video_id = request.form.get('video_id')
            comment_text = request.form.get('comment')
            rating_value = request.form.get('rating')

            if comment_text:
                comment = Comment(
                    video_id=video_id,
                    user_id=session['user_id'],
                    content=comment_text
                )
                db.session.add(comment)

            if rating_value:
                existing_rating = Rating.query.filter_by(video_id=video_id, user_id=session['user_id']).first()
                if existing_rating:
                    existing_rating.rating = int(rating_value)
                else:
                    rating = Rating(
                        video_id=video_id,
                        user_id=session['user_id'],
                        rating=int(rating_value)
                    )
                    db.session.add(rating)

            db.session.commit()
            flash("Feedback submitted!", "success")

        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            flash("Something went wrong", "error")

        return redirect('/dashboard')

    # GET: Search and display videos
    search_query = request.args.get('search', '').strip()
    if search_query:
        videos = Video.query.filter(
            (Video.title.ilike(f'%{search_query}%')) |
            (Video.description.ilike(f'%{search_query}%'))
        ).order_by(Video.uploaded_at.desc()).all()
    else:
        videos = Video.query.order_by(Video.uploaded_at.desc()).all()

    # Prepare video data
    video_data = []
    for video in videos:
        comments = Comment.query.filter_by(video_id=video.id).order_by(Comment.created_at.desc()).all()
        # Load usernames with comments
        for comment in comments:
            comment.user = User.query.get(comment.user_id)

        ratings = Rating.query.filter_by(video_id=video.id).all()
        avg_rating = round(sum(r.rating for r in ratings) / len(ratings), 2) if ratings else None
        user_rating = None
        if 'user_id' in session:
            user_rating_obj = Rating.query.filter_by(video_id=video.id, user_id=session['user_id']).first()
            user_rating = user_rating_obj.rating if user_rating_obj else None

        video_data.append({
            "video": video,
            "comments": comments,
            "avg_rating": avg_rating,
            "user_rating": user_rating
        })

    return render_template('dashboard.html', video_data=video_data)


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