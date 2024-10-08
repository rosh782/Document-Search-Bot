import os
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.utils import secure_filename
import config
from utils import convert_pdf_to_txt, convert_docx_to_txt, save_file_content, allowed_file, file_creation, ask_question
import traceback

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_BINDS'] = config.SQLALCHEMY_BINDS
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = config.ADMIN_SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = config.ALLOWED_EXTENSIONS
app.config['TEXTFILE_FOLDER'] = config.TEXTFILE_FOLDER

with app.app_context():
    file_creation()

files_uploaded = {}

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # This is the login view route name
login_manager.login_message_category = 'info'


# Define User model with Flask-Login's UserMixin
class User(db.Model, UserMixin):
    __bind_key__ = 'primary'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class UploadedFile(db.Model):
    __bind_key__ = 'secondary'  # This tells SQLAlchemy to use the secondary database
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    uploader = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.String(100), nullable=False)


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        is_admin = request.form.get('is_admin')
        admin_key = request.form.get('admin_key')
        role = 'User'

        admin_secret_key = config.ADMIN_SECRET_KEY

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists! Please choose another.', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))

        if is_admin and admin_key == admin_secret_key:
            role = 'Admin'
        elif is_admin and admin_key != admin_secret_key:
            flash('Invalid Secret Key!', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Sign-up successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_mode = request.form.get('role')
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)  # Logs in the user

            # Redirect based on role
            if user_mode == 'admin' and user.role == 'Admin':
                return redirect(url_for('ask'))
            elif user_mode == 'user' and user.role == 'User':
                return redirect(url_for('ask'))
            else:
                flash('Invalid role selected for the user.', 'error')
                return redirect(url_for('login'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/upload', methods=['GET', 'POST'])
@login_required  # Only logged-in users can access this
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)

            if filename.endswith('.pdf'):
                content = convert_pdf_to_txt(file_path)
            elif filename.endswith('.docx'):
                content = convert_docx_to_txt(file_path)
            else:
                with open(file_path, 'r') as f:
                    content = f.read()

            save_file_content(filename, content)
            flash('File uploaded and processed successfully!')

            txt_filename = filename.rsplit('.', 1)[0] + '.txt'
            uploader = current_user.username
            upload_date = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            new_file = UploadedFile(filename=txt_filename, uploader=uploader, upload_date=upload_date)
            db.session.add(new_file)
            db.session.commit()
            return redirect(request.url)

        flash('Invalid file format. Only PDF, DOCX and TXT are allowed.')
        return redirect(request.url)
    return render_template('upload.html')


@app.route('/ask', methods=['GET', 'POST', 'DELETE'])
@login_required
def ask():
    if request.method == 'GET':
        try:
            # Fetch all uploaded files from the database
            files = UploadedFile.query.all()
            file_list = [{'filename': f.filename, 'uploader': f.uploader, 'upload_date': f.upload_date} for f in files]

            # Render the template with the file list
            return render_template('test.html', files=file_list)
        except Exception as e:
            # Log the error traceback for debugging purposes
            print(f"Error occurred: {traceback.format_exc()}")
            return jsonify({'error': 'An error occurred while fetching files.'}), 500

    elif request.method == 'POST':
        question = request.form.get('question')
        filename = request.form.get('filename')

        # Validate that a question and a file have been provided
        if not question:
            return jsonify({'error': 'Please enter a question.'}), 400
        if not filename:
            return jsonify({'error': 'Please select a file.'}), 400

        file_path = os.path.join(app.config['TEXTFILE_FOLDER'], filename)

        # Check if the file exists in the specified folder
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found.'}), 404

        try:
            # Read the content of the selected file
            with open(file_path, 'r') as file:
                file_content = file.read()

            # Call the function to ask the question (replace with your implementation)
            answer = ask_question(file_content, question)

            # Return the answer as a JSON response
            return jsonify({'answer': answer})

        except Exception as e:
            # Log the error traceback for debugging purposes
            print(f"Error occurred: {traceback.format_exc()}")
            return jsonify({'error': f'An error occurred: {str(e)}'}), 500

    elif request.method == 'DELETE':
        try:
            # Parse JSON data from the request body
            request_data = request.get_json()
            print(f"Request data: {request_data}")  # Debug log for incoming data

            filename = request_data.get('filename')  # Extract filename from JSON data

            if not filename:
                return jsonify({'error': 'No file selected for deletion.'}), 400

            # Find the file in the database
            file_to_delete = UploadedFile.query.filter_by(filename=filename).first()

            if not file_to_delete:
                return jsonify({'error': 'File not found in the database.'}), 404

            # Remove the file entry from the database
            db.session.delete(file_to_delete)
            db.session.commit()

            # Delete the file from the file system
            file_path = os.path.join(app.config['TEXTFILE_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)

            return jsonify({'message': f'File {filename} successfully deleted.'}), 200

        except Exception as e:
            print(f"Error occurred: {traceback.format_exc()}")
            return jsonify({'error': f'An error occurred while deleting the file: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)
