import base64
import os
import shutil

from flask import request, render_template, redirect, url_for, session
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes  # Import hashes module
from hvac import Client

import string
import secrets
import uuid
from cryptography.fernet import Fernet
import base64
from flask import send_file,jsonify
from cryptography.fernet import Fernet

import bcrypt  # Import the bcrypt library
import mail
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from flask_sqlalchemy import SQLAlchemy
from flask import session
from flask import flash
import random
from flask import Flask, render_template, request, redirect, url_for
from flask_mail import Mail, Message
import string
import secrets
import bcrypt
import hashlib
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from sqlalchemy.orm import aliased
import hvac

from sqlalchemy.orm.exc import NoResultFound  # Import NoResultFound
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mariadb+pymysql://root:Root123456789;@localhost/sfs'
db = SQLAlchemy(app)

# Flask-Mail configuration for Gmail SMTP
app.config['SECRET_KEY'] = "GENERATE SECRET KEY AND PUT HERE"
app.config['MAIL_SERVER'] = 'SMTP SERVER/SERVICE'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'YOUR SERVICE EMAIL HERE'
app.config['MAIL_PASSWORD'] = 'YOUR EMAIL PASSWORD HERE'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 100000  # 30 minutes (30 * 60 seconds)
app.config['UPLOAD_FOLDER'] = "uploads"
mail = Mail(app)

# Define the Vault client (the following are for a temporary test vault, please change)
app.config['VAULT_URL'] = 'https://127.0.0.1:8200'
app.config['VAULT_TOKEN'] = 'PUT VAULT TOKEN HERE'  # This should be a valid Vault token with write access
app.config['VAULT_CLIENT_CERT_PATH'] = "PATH TO vault-cert.pem"
app.config['VAULT_CLIENT_KEY_PATH'] = "PATH TO vault-key.pem"
app.config['VAULT_SERVER_CERT_PATH'] = "PATH TO vault-ca.pem"
app.config['VAULT_KEYS_PATH'] = 'foo'

hvac_client = hvac.Client(url=app.config['VAULT_URL'], token=app.config['VAULT_TOKEN'],
                          cert=(app.config['VAULT_CLIENT_CERT_PATH'], app.config['VAULT_CLIENT_KEY_PATH']),
                          verify=app.config['VAULT_SERVER_CERT_PATH'], )


def encode_key(key):
    # Assuming 'key' is in bytes format
    encoded_key = base64.b64encode(key).decode('utf-8')  # Encode bytes to base64 and decode to string
    return encoded_key


def decode_key(encoded_key):
    decoded_key = base64.b64decode(encoded_key.encode('utf-8'))
    return decoded_key


# ...
def put_key(path, data):

    hvac_client.secrets.kv.v2.create_or_update_secret(path=path, secret={'data': {}})
    print(f"Path {path} created in the kv engine")

    # Create or update the secret within the specified path
    hvac_client.secrets.kv.v2.create_or_update_secret(path=path, secret={'data': data})
    print(f"Secret written to {path}")


def get_key(identifier):
    read_response = hvac_client.secrets.kv.read_secret_version(path=identifier)
    val=read_response['data']['data']['data']
    return val


def get_shared_files_for_user(user):
    user_groups = user.groups

    # Create a list of group IDs the user belongs to
    group_ids = [group.id for group in user_groups]

    # Query files that are uploaded by users in any of the user's groups
    shared_files = File.query.filter(File.uploaded_by.has(UserGroups.group_id.in_(group_ids))).all()

    return shared_files


def is_otp_expired(last_otp_generation_time):
    if last_otp_generation_time:
        valid_time_window = timedelta(minutes=1)
        current_time = datetime.utcnow()
        return (current_time - last_otp_generation_time) > valid_time_window
    return True


def send_password_by_email(username, email, password):
    msg = Message('Your New Account Information', sender='donotreply@sfs.com', recipients=[email])
    msg.body = f"Hello {username},\n\nYour new account has been created with the following credentials:\n\nUsername: {username}\nPassword: {password}\n\nPlease change your password after logging in for security reasons.\n\nBest regards,\nYour Application Team"

    try:
        mail.send(msg)
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {str(e)}")


def generate_otp():
    return str(random.randint(100000, 999999))


def generate_random_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


# Helper function to hash a password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def send_otp_email(email, otp):
    msg = Message('Your Login OTP', sender='your_email@gmail.com', recipients=[email])
    msg.body = f'Your OTP for login is: {otp}'
    try:
        mail.send(msg)
        print("OTP sent successfully.")
    except Exception as e:
        print(f"Error sending OTP email: {str(e)}")


#

# Function to derive a key using PBKDF2
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


# Function to encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(iv + ciphertext)



def decrypt_file(encrypted_file_path, key):
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Extract the IV (Initialization Vector) from the encrypted data
    iv = encrypted_data[:16]

    # Extract the ciphertext from the encrypted data
    ciphertext = encrypted_data[16:]

    # Create a cipher object for decryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Get the original file path without the '.enc' extension
    original_file_path = encrypted_file_path[:-4]

    # Write the decrypted data to the original file path
    with open(original_file_path, 'wb') as original_file:
        original_file.write(decrypted_data)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    two_factor_secret = db.Column(db.String(128))
    verification_code = db.Column(db.String(6))
    last_otp_generation_time = db.Column(db.DateTime)
    first_login = db.Column(db.Boolean, default=True)  # Indicates if it's the user's first login

    groups = db.relationship(
        'Groups',
        secondary='user_groups',
        back_populates='users'
    )

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    date_of_upload = db.Column(db.TIMESTAMP, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    size = db.Column(db.BigInteger)  # Use an appropriate SQLAlchemy data type for size
    user = db.relationship('User', backref='files')


class Groups(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    expiry_date = db.Column(db.Date)  # Add this line to define the expiry_date attribute
    users = db.relationship(
        'User',
        secondary='user_groups',
        back_populates='groups'
    )

class UserGroups(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), primary_key=True)


class FileDownloads(db.Model):
    DownloadID = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    DownloadDate = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref='downloads')
    file = db.relationship('File', backref='downloads')

class Access(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), primary_key=True)


class FileGroups(db.Model):
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), primary_key=True)
    file = db.relationship('File', backref='file_groups')
    group = db.relationship('Groups', backref='file_groups')





@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if request.method == 'POST':
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if new_password == confirm_password:
                # Update the user's password
                user.password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                user.first_login = False  # Mark the user's first login as completed
                db.session.commit()
                flash('Password changed successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Passwords do not match', 'error')

        return render_template('change_password.html')
    else:
        return redirect(url_for('index'))



@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')
@app.route('/login', methods=['POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    username = request.form.get('username')
    password = request.form.get('password')

    # Verify username and password (implement your authentication logic here)
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        # User authenticated, generate and send OTP
        otp = generate_otp()
        send_otp_email(user.email, otp)

        # Update the last OTP generation time
        user.last_otp_generation_time = datetime.utcnow()


        # Store user's OTP in the database
        user.verification_code = otp


        # Store user's secret in the database (You should generate and store this secret securely)
        user.two_factor_secret = 'your_generated_secret'  # Replace with your generated secret

        db.session.commit()

        # Store user_id in the session temporarily
        session['user_id'] = user.id

        return render_template('verify_otp.html')
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    MAX_TRIES = 3  # Define the maximum number of OTP verification attempts allowed

    if 'user_id' in session:
        user_id = session['user_id']
        entered_otp = request.form.get('otp')
        tries = session.get('otp_verification_tries', 0)

        # Retrieve the user from the database
        user = User.query.get(user_id)

        if user:
            if is_otp_expired(user.last_otp_generation_time):
                flash('OTP has expired. Please login again and use the new one.', 'error')
                session.pop('temp_otp', None)
                session.pop('user_id', None)
                session.pop('otp', None)
                session.pop('otp_verification_tries', None)
                return redirect(url_for('index'))

            if entered_otp == user.verification_code:
                # OTP is correct, clear the temporary OTP and set the session OTP
                session.pop('temp_otp', None)
                session['otp'] = user.verification_code

                flash('OTP verification successful', 'success')
                session.pop('otp_verification_tries', None)  # Reset the attempt count
                if user.first_login:
                    # Redirect to change password route
                    session['user_id'] = user.id  # Store user_id in session temporarily
                    return redirect(url_for('change_password'))

                return redirect(url_for('dashboard'))
            else:
                tries += 1
                flash('Invalid OTP', 'error')
                if tries >= MAX_TRIES:
                    flash('Too many unsuccessful attempts. Please login again.', 'error')
                    session.pop('temp_otp', None)
                    session.pop('user_id', None)
                    session.pop('otp', None)
                    session.pop('otp_verification_tries', None)
                    return redirect(url_for('index'))
                else:
                    session['otp_verification_tries'] = tries
                    return render_template('verify_otp.html')
        else:
            flash('User not found', 'error')
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))






#
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('otp', None)
    return redirect(url_for('index'))






@app.route('/admin')
def admin():
    users = User.query.all()
    groups = Groups.query.all()
    return render_template('admin.html', groups=groups, users=users)

@app.route('/create_group', methods=['POST'])
def create_group():
    name = request.form.get('group_name')
    expiry_date = request.form.get('expiry_date')

    group = Groups(name=name, expiry_date=datetime.strptime(expiry_date, '%Y-%m-%d') if expiry_date else None)
    db.session.add(group)
    db.session.commit()
    os.makedirs("./uploads/" + name)
    return redirect(url_for('admin'))



@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.form.get('username')
    email = request.form.get('email')
    group_id = request.form.get('group')

    group = Groups.query.get(group_id)

    if group:
        # Generate a random strong password
        password = generate_random_password()
        # Send the generated password by email
        send_password_by_email(username, email, password)
        user = User(username=username, password_hash=hash_password(password), email=email)
        user.groups.append(group)
        db.session.add(user)
        db.session.commit()
    else:
        # Handle the case where the group does not exist
        flash("Group not found.")

    return redirect(url_for('admin'))


def export_entries_by_group_id(group_id):
    # Fetch entries in FileDownloads with the given group_id
    file_downloads = FileDownloads.query.join(FileGroups).filter(FileGroups.group_id == group_id).all()

    # Process or export the fetched entries
    for download_entry in file_downloads:
        # Process each download entry here
        print(
            f"Download ID: {download_entry.DownloadID}, File ID: {download_entry.file_id}, User ID: {download_entry.user_id}, Download Date: {download_entry.DownloadDate}")



from sqlalchemy.exc import IntegrityError
@app.route('/delete_group/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    group = Groups.query.get(group_id)
    # Fetch file_ids associated with the given group_id in FileGroups
    print(group)
    if group:
        group_name = group.name
        file_ids = [file_group.file_id for file_group in FileGroups.query.filter_by(group_id=group_id).all()]
        print(file_ids)
            # Delete Access entries associated with the file_ids
        Access.query.filter(Access.file_id.in_(file_ids)).delete(synchronize_session=False)

            # Delete UserGroups entries associated with the group_id
        UserGroups.query.filter_by(group_id=group_id).delete()

            # Delete FileDownloads entries associated with the file_ids
        FileDownloads.query.filter(FileDownloads.file_id.in_(file_ids)).delete(synchronize_session=False)

            # Delete FileGroups entries associated with the group_id
        FileGroups.query.filter_by(group_id=group_id).delete()

            # Delete File entries associated with the file_ids
        File.query.filter(File.id.in_(file_ids)).delete(synchronize_session=False)

            # Delete the group itself
        Groups.query.filter_by(id=group_id).delete()

            # Commit changes to the database
        db.session.commit()
            # Delete the directory
        directory_path = os.path.join(app.config['UPLOAD_FOLDER'], group_name)
        if os.path.exists(directory_path):
            shutil.rmtree(directory_path)
            print(f"Directory '{directory_path}' deleted successfully.")
        else:
            print(f"Directory '{directory_path}' not found.")

        return redirect(url_for('admin'))

    else:
        print(f"No files or groups found with ID {group_id}. Nothing to delete.")

    return redirect(url_for('admin'))

@app.route('/user/<int:user_id>')
def user_details(user_id):
    user = User.query.get(user_id)
    groups = Groups.query.all()
    return render_template('user_details.html', user=user, groups=groups)


@app.route('/add_user_to_group/<int:user_id>', methods=['POST'])
def add_user_to_group(user_id):
    group_id = request.form.get('group')
    user = User.query.get(user_id)
    group = Groups.query.get(group_id)

    if user and group:
        user.groups.append(group)
        db.session.commit()

    return redirect(url_for('user_details', user_id=user_id))


@app.route('/remove_user_from_group/<int:user_id>/<int:group_id>')
def remove_user_from_group(user_id, group_id):
    user = User.query.get(user_id)
    group = Groups.query.get(group_id)

    if user and group:
        user.groups.remove(group)
        db.session.commit()

    return redirect(url_for('user_details', user_id=user_id))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Delete entries in FileDownloads table for files uploaded by the user
    file_downloads = FileDownloads.query.join(File).filter(File.uploaded_by == user_id).all()
    for file_download in file_downloads:
        db.session.delete(file_download)




    # Get files uploaded by the user
    files_uploaded = File.query.filter_by(uploaded_by=user_id).all()

    # Get the user's groups
    user_groups = Groups.query.join(UserGroups).filter(UserGroups.user_id == user_id).all()

    # Delete files uploaded by the user and print group names before deletion
    for file in files_uploaded:
        # group_names = [group.name for group in user_groups if file in group.files]
        group_names = [group.name for group in user_groups for fg in group.file_groups if fg.file_id == file.id]
        for group_name in group_names:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], group_name, file.name)
            print(f"Deleting file: {file_path}")
            os.remove(file_path)



    # Delete entries in Access table for files uploaded by the user
    for file in files_uploaded:
        Access.query.filter_by(file_id=file.id).delete()
    # Delete entries in FileGroups table for files uploaded by the user
    for file in files_uploaded:
        FileGroups.query.filter_by(file_id=file.id).delete()

    groups_for_file = [group.name for group in file.file_groups]
    for file in groups_for_file :
        print(app.config['UPLOAD_FOLDER'] + '/' + file)
        # os.remove(app.config['UPLOAD_FOLDER'] + '/' +  + "/" + file)


    for file in files_uploaded:
        FileGroups.query.filter_by(file_id=file.id).delete()

    # Delete the files uploaded by the user
    File.query.filter_by(uploaded_by=user_id).delete()

    # Delete entries in UserGroups table matching the user_id
    UserGroups.query.filter_by(user_id=user_id).delete()

    # Delete the user entry in the User table
    User.query.filter_by(id=user_id).delete()


    # Commit the changes
    db.session.commit()

    return redirect(url_for('admin'))  # Redirect to the admin page or another appropriate page


@app.route('/dashboard')
def dashboard():

    if 'user_id' in session and 'otp' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        # Get the groups that the user belongs to
        user_groups = user.groups

        # Create a dictionary to store files for each group with uploader's username
        group_files = {}

        # Iterate through user's groups
        for group in user_groups:
            group_id = group.id
            group_name = group.name

            # Retrieve files associated with the current group using the FileGroups table
            files = db.session.query(
                File.id,
                File.name,
                File.date_of_upload,
                File.size,
                User.username.label('uploaded_by_username')
            ).join(FileGroups, File.id == FileGroups.file_id).join(User, File.uploaded_by == User.id).filter(
                FileGroups.group_id == group_id
            ).all()

            group_files[group_name] = {
                'group_id': group_id,
                'files': files
            }

        return render_template('dashboard.html', user=user, group_files=group_files)
    else:
        return redirect(url_for('index'))



@app.route('/download/file/<int:group_id>/<int:file_id>')
def download_file(group_id, file_id):
    if 'user_id' not in session:
        return "User not logged in", 401

    user_id = session['user_id']
    user = User.query.get(user_id)
    file = File.query.get(file_id)

    if not user or not file:
        flash('User or file not found', 'error')
        return redirect(url_for('download_history'))

    # Ensure that the file belongs to the specified group
    group = Groups.query.get(group_id)
    if group not in user.groups:
        flash('User does not have access to this group', 'error')
        return redirect(url_for('dashboard'))


    # Record the file download in the FileDownloads table
    download_record = FileDownloads(user_id=user_id, file_id=file_id, DownloadDate=datetime.now())
    db.session.add(download_record)
    db.session.commit()
    user_id = session['user_id']
    user = User.query.get(user_id)
    # Get the groups that the user belongs to
    # user_groups = user.groups
    # for group in user_groups:
    #     logged_user_group_id = group.id
    #     group_name = group.name
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], group.name, file.name)
    print(file_path)
    # Proceed with downloading the file (as shown in the previous code)

    decrypt_file(file_path,decode_key(get_key(file_id)))

    return send_file(file_path, as_attachment=True)

@app.route('/download/history/<int:group_id>/<int:file_id>')
def download_history(group_id, file_id):

    user_id = session['user_id']
    user = User.query.get(user_id)
    group = Groups.query.get(group_id)

    if user_id is None:
        flash('User not logged in', 'error')
        return redirect(url_for('login'))  # Redirect to the login page or any appropriate page

    group = Groups.query.get(group_id)
    if group not in user.groups:
        flash('User does not have access to this group', 'error')
        return redirect(url_for('dashboard'))


    # Retrieve the file record by file_id
    # file = File.query.get(file_id)
    file = db.session.query(File).filter_by(id=file_id).join(FileGroups).filter_by(group_id=group_id).first()
    if file is None:
        flash('File not found or not in the specified group', 'error')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard or an appropriate page

    if group and file:
        # Retrieve the download history for the file within the specified group
        download_history = db.session.query(FileDownloads.DownloadDate, User.username). \
            join(User, FileDownloads.user_id == User.id). \
            filter(FileDownloads.file_id == file_id).all()


        return render_template('file.html', file=file, download_history=download_history, group=group)
    else:
        # Handle the case where the file doesn't exist
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))





@app.route('/upload/<int:group_id>', methods=['GET', 'POST'])
def upload_file(group_id):
    if 'user_id' not in session:
        return "User not logged in", 401

    user_id = session['user_id']
    user = User.query.get(user_id)
    group = Groups.query.get(group_id)
    if group not in user.groups:
        flash('User does not have access to this group', 'error')
        return redirect(url_for('dashboard'))

    user_id = session['user_id']
    user = User.query.get(user_id)

    # Verify if the user belongs to the specified group
    group = Groups.query.get(group_id)
    if group is None:
        return "Group not found", 404

    # # Verify if the user belongs to the specified group
    # if not user.groups.filter(Groups.id == group_id).any():
    #     return "User does not have access to this group", 403

    if request.method == 'POST':
        uploaded_file = request.files['file']

        if uploaded_file:

            # Define the upload folder based on group name and file name
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], group.name)
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, uploaded_file.filename)
            print("file_path type = " + str((type(file_path))))

            # Save the uploaded file to the defined path
            uploaded_file.save(file_path)

            # Calculate the file size in bytes
            file_size = os.path.getsize(file_path)

            # Create a new File record
            file = File(name=uploaded_file.filename, date_of_upload=datetime.now(), uploaded_by=user_id, size=file_size)

            db.session.add(file)
            db.session.commit()

            # Create a new Access record for the user and file
            access = Access(user_id=user_id, file_id=file.id)
            db.session.add(access)

            # Send the encryption key to HashiCorp Vault
            # Derive key and encrypt the file
            password = "ee"
            salt = os.urandom(16)
            key = derive_key(password, salt)
            encrypt_file(file_path, key)

            # Send the encryption key to HashiCorp Vault
            print("file.id : ", file.id)
            print("key : ", key, " and is of type : ", type(key))
            put_key(file.id, encode_key(key))
            print(get_key(file.id))

            # Create a new FileGroups record to associate the file with the group
            file_group = FileGroups(file_id=file.id, group_id=group_id)
            db.session.add(file_group)

            db.session.commit()

            os.remove(file_path)
            os.rename(file_path + ".enc", file_path)




    return render_template('upload.html', user=user, group=group)




if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)

    # app.run(ssl_context='adhoc')
    app.run(host='0.0.0.0', ssl_context='adhoc', port=81, debug=True)