# Import Flask and other necessary modules
from flask import Flask, render_template, request, redirect, url_for, session, send_file

# import encryption
from encryption_AES import encrypt_data, decrypt_data
from encryption_RSA_client import load_public_key, encrypt_with_rsa
from encryption_RSA_server import load_private_key, decrypt_with_rsa
from encryption_RSA_file import decrypt_message
# import dataset
from database_username import username_database, search_email, search_email_patient, search_email_doctor
from email_database import insert_email, search_email_data, insert_pin
from database_login_too_many_wrong_attempt import search_attempts, check_and_update_login_attempts, search_last_entry_time

# Other functions
from register_password_strength import validate_password

# Python library
import requests
from datetime import datetime, timedelta
import base64
import random
import string
import OpenSSL.crypto
from OpenSSL import crypto, SSL
import ssl

"""The client-side server:
Server is responsible for handling user input and serving requested pages. 
There are two databases: 
-database_username: store users' email addresses and usernames, which serves as the initial step to filter out 
incorrect users and is also used to retrieve passwords.
-database_error_attempts: database is used to store login error information. After multiple consecutive login failures, 
access for the user associated with that username will be denied for 30 minutes.
Public page: 
-Homepage: a brief introduction to our design. 
-Contact Us page: a details of our group members.
Private page: according to session['type']
-Patient Home page: only available for patient to check their personal information, 
-Admission Page: only available for doctor to check system activities. 
-Change Password: only available to all logged-in users. 

"""

# Create a Flask app
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
public_key = load_public_key("public_key.pem")
private_key = load_private_key('private_key_client.pem')

# Define routes

'''Public page'''


# Homepage
@app.route('/')
def home():
    session['type'] = 'logout'
    return render_template('home.html', type=session.get('type'))


# Contact US page
@app.route('/contact_us')
def contact_us():
    return render_template('contact_us.html', type=session.get('type'))


'''Login in related function'''


# index page
@app.route('/index')
def index():
    return render_template('index.html')


# log out
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # clear session
    session.pop('correct_pin', None)
    session.pop('email', None)
    session.pop('username', None)
    session.pop('password', None)
    session['type'] = 'logout'
    session.pop('page', None)
    return render_template('home.html', type=session['type'])


# log in page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Encrypt the username for database search
        encrypted_username = encrypt_data(username)
        encrypted_password = encrypt_data(password)

        # Check if the user exists in the database
        if username_database('patient', 'search', encrypted_username, None):
            # Access to an error database to check error times
            attempts = search_attempts(encrypted_username)
            print(attempts)
            if attempts < 2:  # within allowance (2 times)
                # store required values
                session['type'] = 'patient'
                session['username'] = username
                session['password'] = encrypted_password
                session['page'] = 'login'
                search_data = search_email_patient(encrypted_username)
                email = decrypt_data(search_data)
                session['email'] = email
                # check whether robot
                return redirect(url_for('verify_robot'))
            else:  # waiting
                # calculate the waiting time
                current_time = datetime.now()
                last_entry_time = search_last_entry_time(username)
                last_entry_time = datetime.strptime(last_entry_time, '%Y-%m-%d %H:%M:%S')
                remaining_seconds = (last_entry_time + timedelta(minutes=30) - current_time).total_seconds()
                remaining_minutes, remaining_seconds = divmod(remaining_seconds, 60)
                # return error message
                error_message = "Attempt too many, please waiting.", "{:.0f} minutes {:.0f} seconds".format(
                    remaining_minutes, remaining_seconds)
                return render_template('login.html', error=error_message)
        else:
            error_message = "Invalid username. Please try again."
            return render_template('login.html', error=error_message)
    return render_template('login.html')


# register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        # encrypted aes
        encrypted_username = encrypt_data(username)
        encrypted_email = encrypt_data(email)

        # Check if the user exists in the database
        if username_database('patient', 'search', encrypted_username, encrypted_email):
            error_message = "The username have already existed. Please try again"
            return render_template('register.html', error=error_message)

        # Check if the email exists in the database
        if search_email(encrypted_email):
            error_message = "The email have already existed. Please try again"
            return render_template('register.html', error=error_message)

        # Check if password meet required
        valid, message = validate_password(username, password, confirm_password)
        if not valid:
            return render_template('register.html', error=message)

        # store input
        session['email'] = email
        session['username'] = username
        session['password'] = password
        session['page'] = 'register'
        session['type'] = 'patient'
        return redirect(url_for('verify_robot'))

    # If it's a GET request, render the registration form
    return render_template('register.html')


# doctor login page
@app.route('/doctor', methods=['GET', 'POST'])
def doctor():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Encrypt the username for database search
        encrypted_username = encrypt_data(username)
        encrypted_password = encrypt_data(password)

        # Check if the user exists in the database
        if username_database('doctor', 'search', encrypted_username, None):
            # Access to an error database to check error times
            attempts = search_attempts(encrypted_username)
            if attempts < 2:  # within allowance (2 times)
                # store required values
                session['type'] = 'doctor'
                session['username'] = username
                session['password'] = encrypted_password
                session['page'] = 'doctor'
                search_data = search_email_doctor(encrypted_username)
                email = decrypt_data(search_data)
                session['email'] = email
                # check whether robot
                return redirect(url_for('verify_robot'))
            else:  # waiting
                # calculate the waiting time
                current_time = datetime.now()
                last_entry_time = search_last_entry_time(username)
                last_entry_time = datetime.strptime(last_entry_time, '%Y-%m-%d %H:%M:%S')
                remaining_seconds = (last_entry_time + timedelta(minutes=30) - current_time).total_seconds()
                remaining_minutes, remaining_seconds = divmod(remaining_seconds, 60)
                # return error message
                error_message = "Attempt too many, please waiting.", "{:.0f} minutes {:.0f} seconds".format(
                    remaining_minutes, remaining_seconds)
                return render_template('doctor.html', error=error_message)
        else:
            error_message = "Invalid username. Please try again."
            return render_template('doctor.html', error=error_message)
    return render_template('doctor.html')


# forget password page
@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        # Encrypt the username for database search
        encrypted_username = encrypt_data(username)
        encrypted_email = encrypt_data(email)

        # Check if the user exists in the database
        if username_database('patient', 'search', encrypted_username, None):
            attempts = search_attempts(username)
            if attempts < 2:
                if encrypted_email == search_email_patient(encrypted_username):
                    check_and_update_login_attempts(username, 200)
                    session['email'] = email
                    session['username'] = username
                    session['page'] = 'forget'
                    session['type'] = 'patient'
                    return redirect(url_for('verify_robot'))
                else:
                    error_message = "Incorrect email. Please try again."
                    check_and_update_login_attempts(username, 400)
                    return render_template('forget_password.html', error=error_message)
            else:
                current_time = datetime.now()
                last_entry_time = search_last_entry_time(username)
                last_entry_time = datetime.strptime(last_entry_time, '%Y-%m-%d %H:%M:%S')
                remaining_seconds = (last_entry_time + timedelta(minutes=30) - current_time).total_seconds()
                remaining_minutes, remaining_seconds = divmod(remaining_seconds, 60)
                error_message = "Attempt too many, please waiting.", "{:.0f} minutes {:.0f} seconds".format(
                    remaining_minutes,
                    remaining_seconds)
                return render_template('forget_password.html', error=error_message)
        else:
            error_message = "Invalid username. Please try again."
            return render_template('forget_password.html', error=error_message)
    return render_template('forget_password.html')


'''verification whether robot or not'''


# check whether is robot or not
@app.route('/verify_robot')
def verify_robot():
    captcha = generate_captcha()
    return render_template('not_robot.html', captcha=captcha)


# create captcha
def generate_captcha():
    captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return captcha


# not_robot page
@app.route('/verify', methods=['POST'])
def verify():
    user_input = request.form.get('captcha')
    captcha = request.form.get('captcha_code')

    if user_input.lower() == captcha.lower():
        email = session.get('email')
        return render_template('confirm_email.html', email=mask_email(email), username=session['username'])
    else:
        captcha = generate_captcha()
        return render_template('not_robot.html', captcha=captcha, error='Please try again')


'''verification email'''


# mask email
def mask_email(email):
    # Split the email address into the username and domain parts
    username, domain = email.split('@')
    # Get the first three characters of the username
    masked_username = username[:3]
    # Replace the remaining characters with 'x's
    masked_username += 'x' * (len(username) - 3)
    # Return the masked email address with a dot before "com"
    return f"{masked_username}@{domain}"


# generating and sending random pin
@app.route('/generate_pin', methods=['GET'])
def generate_pin():
    # Generate a random 6-digit pin
    email = session.get('email')
    encrypted_email = encrypt_data(email)
    random_pin = ''.join(random.choices('0123456789', k=6))
    encrypted_pin = encrypt_data('PIN: ' + random_pin)
    # send pin to email
    if search_email_data(encrypted_email) is not None:
        insert_pin(encrypted_pin, encrypted_email)
    else:
        insert_email(encrypted_email)
        insert_pin(encrypted_pin, encrypted_email)
    session['correct_pin'] = random_pin
    # Render the register template with the generated pin
    return render_template('confirm_email.html', message='Pin has already sent to your email', email=mask_email(email),
                           username=session['username'])


# pin verification
@app.route('/verify_pin', methods=['POST'])
def verify_pin():
    # Get the pin entered by the user
    pin_entered = request.form.get('pin')
    email = session.get('email')

    if pin_entered == session.get('correct_pin'):
        message = 'Pin is correct'
        # login page
        if session.get('page') == 'login':
            username = encrypt_data(session.get('username'))
            password = session.get('password')
            encrypted_aes_username = encrypt_with_rsa(public_key, username)
            encrypted_aes_password = encrypt_with_rsa(public_key, password)
            encoded_username = base64.b64encode(encrypted_aes_username).decode('utf-8')
            encoded_password = base64.b64encode(encrypted_aes_password).decode('utf-8')

            response = requests.post('http://127.0.0.1:5001/',
                                     json={'page': 'login', 'username': encoded_username,
                                           'password': encoded_password})

            # Check the response from the server
            if response.status_code == 200:
                check_and_update_login_attempts(username, 200)
                session.pop('correct_pin', None)
                session.pop('password', None)
                session.pop('page', None)
                return render_template('home.html', type=session['type'])
            elif response.status_code == 300:
                check_and_update_login_attempts(username, 200)
                session.pop('correct_pin', None)
                session.pop('password', None)
                session.pop('page', None)
                data = response.json()
                encrypted_aes_password = base64.b64decode(data['password'])
                aes_password = decrypt_with_rsa(private_key, encrypted_aes_password)
                session['password'] = aes_password
                return render_template('warning.html', type=session['type'], time=data['time'],
                                       username=session['username'])
            else:
                # Password is incorrect, render login page with an error message
                error_message = "Incorrect password. Please try again."
                check_and_update_login_attempts(username, 400)
                return render_template('login.html', error=error_message)

        # doctor page
        elif session.get('page') == 'doctor':
            username = encrypt_data(session.get('username'))
            password = session.get('password')
            # send to server
            encrypted_aes_username = encrypt_with_rsa(public_key, username)
            encrypted_aes_password = encrypt_with_rsa(public_key, password)
            encoded_username = base64.b64encode(encrypted_aes_username).decode('utf-8')
            encoded_password = base64.b64encode(encrypted_aes_password).decode('utf-8')
            response = requests.post('http://127.0.0.1:5001/',
                                     json={'page': 'doctor', 'username': encoded_username,
                                           'password': encoded_password})

            # Check the response from the server
            if response.status_code == 200:
                check_and_update_login_attempts(username, 200)
                session.pop('correct_pin', None)
                session.pop('password', None)
                session.pop('page', None)
                return render_template('home.html', type=session['type'])
            elif response.status_code == 300:
                check_and_update_login_attempts(username, 200)
                session.pop('correct_pin', None)
                session.pop('password', None)
                session.pop('page', None)
                data = response.json()
                encrypted_aes_password = base64.b64decode(data['password'])
                aes_password = decrypt_with_rsa(private_key, encrypted_aes_password)
                session['password'] = aes_password
                return render_template('warning.html', type=session['type'], time=data['time'],
                                       username=session['username'])
            else:
                # Password is incorrect, render login page with an error message
                error_message = "Incorrect password. Please try again."
                check_and_update_login_attempts(username, 400)
                return render_template('login.html', error=error_message)
        # register page
        elif session.get('page') == 'register':
            username = encrypt_data(session.get('username'))
            password = encrypt_data(session.get('password'))
            store_email = encrypt_data(email)
            encrypted_aes_username = encrypt_with_rsa(public_key, username)
            encrypted_aes_password = encrypt_with_rsa(public_key, password)
            encoded_username = base64.b64encode(encrypted_aes_username).decode('utf-8')
            encoded_password = base64.b64encode(encrypted_aes_password).decode('utf-8')

            response = requests.post('http://127.0.0.1:5001/',
                                     json={'page': 'register', 'username': encoded_username,
                                           'password': encoded_password})

            # Check the response from the server
            if response.status_code == 201:
                username_database('patient', 'insert', username, store_email)
                # Clear the correct_pin from the session
                session.pop('correct_pin', None)
                session.pop('email', None)
                session.pop('username', None)
                session.pop('password', None)
                session.pop('type', None)
                session.pop('page', None)
                return render_template('login.html')
            else:
                # Error store
                message = "Sorry the server is unreachable. Please try again."
                return render_template('confirm_email.html', message=message, email=mask_email(email),
                                       username=session['username'])
        # forget password page
        elif session.get('page') == 'forget':
            email_n = session.get('email')
            username_n = session.get('username')
            emailen = encrypt_data(session.get('email'))
            username = encrypt_data(session.get('username'))
            encrypted_aes_email = encrypt_with_rsa(public_key, emailen)
            encrypted_aes_username = encrypt_with_rsa(public_key, username)
            encoded_username = base64.b64encode(encrypted_aes_username).decode('utf-8')
            encoded_email = base64.b64encode(encrypted_aes_email).decode('utf-8')
            response = requests.post('http://127.0.0.1:5001/',
                                     json={'page': 'forget', 'username': encoded_username, 'email': encoded_email})
            # Check the response from the server
            if response.status_code == 202:
                session.pop('correct_pin', None)
                session.pop('email', None)
                session.pop('username', None)
                session.pop('password', None)
                session.pop('type', None)
                session.pop('page', None)
                return render_template('sent_password.html', email=mask_email(email_n), username=username_n)
            else:
                # Error store
                message = "Sorry the server is unreachable. Please try again."
                return render_template('confirm_email.html', message=message, email=mask_email(email),
                                       username=session['username'])
        # change password
        elif session.get('page') == 'change_password':
            username = encrypt_data(session.get('username'))
            password = session.get('password')
            encrypted_aes_username = encrypt_with_rsa(public_key, username)
            encrypted_aes_password = encrypt_with_rsa(public_key, password)
            encoded_username = base64.b64encode(encrypted_aes_username).decode('utf-8')
            encoded_password = base64.b64encode(encrypted_aes_password).decode('utf-8')

            response = requests.post('http://127.0.0.1:5001/',
                                     json={'page': 'change_password', 'username': encoded_username,
                                           'password': encoded_password, 'type': session.get('type')})

            # Check the response from the server
            if response.status_code == 204:
                session.pop('correct_pin', None)
                session.pop('password', None)
                session.pop('page', None)
                message = 'Password changed successfully'
                return render_template('change_password.html', type=session.get('type'),
                                       username=session.get('username'), message=message)
            elif response.status_code == 402:  # error same password
                session.pop('correct_pin', None)
                session.pop('password', None)
                session.pop('page', None)
                message = 'New password is not change please try again.'
                return render_template('change_password.html', type=session.get('type'),
                                       username=session.get('username'), error=message)
            else:  # error same password
                session.pop('correct_pin', None)
                session.pop('password', None)
                session.pop('page', None)
                message = 'Error, please try again.'
                return render_template('change_password.html', type=session.get('type'),
                                       username=session.get('username'), error=message)

    else:
        message = 'Pin is incorrect'
    return render_template('confirm_email.html', message=message, email=mask_email(email), username=session['username'])


'''Private page'''


# page show warning about not available
@app.route('/sorry', methods=['GET', 'POST'])
def sorry():
    return render_template('sorry.html', type=session.get('type'))


# change password page

# patient home page: only available for patient
@app.route('/patient_page', methods=['GET', 'POST'])
def patient_page():
    # check permission
    if session.get('type') == 'patient':
        username = session.get('username')
        encrypted_username = encrypt_data(username)  # aes
        encrypted_aes_username = encrypt_with_rsa(public_key, encrypted_username)  # rsa for transmission
        encoded_username = base64.b64encode(encrypted_aes_username).decode('utf-8')
        response = requests.post('http://127.0.0.1:5001/',
                                 json={'page': 'patient_page', 'username': encoded_username})
        # Check the response from the server
        if response.status_code == 203:
            data = response.json()  # Extract JSON data from response
            decrypted_dict = decrypt_dictionary_values(data)  # Decrypt the data
            decrypted_data = {
                'Type': decrypted_dict['Type'],
                'Name': decrypted_dict['Name'],
                'Date Of Birth': decrypted_dict['Date Of Birth'],
                'Gender': decrypted_dict['Gender'],
                'Address': decrypted_dict['Address'],
                'Phone': decrypted_dict['Phone'],
                'Medical Record Number': decrypted_dict['Medical Record Number'],
                'Allergies': decrypted_dict['Allergies'],
                'Current Medications': decrypted_dict['Current Medications'],
                'Past Medical Conditions': decrypted_dict['Past Medical Conditions'],
                'Family Medical History': decrypted_dict['Family Medical History'],
            }
            return render_template('patient_home.html', data=decrypted_data,
                                   type=session.get('type'))  # Pass decrypted data to template
        else:
            return render_template('sorry.html', type='server error')
    else:
        return render_template('sorry.html', type=session.get('type'))


# decryption items in dictionary to send dictionary to page to draw table
def decrypt_dictionary_values(dictionary):
    decrypted_dict = {}
    for key, value in dictionary.items():
        encrypted_aes_value = base64.b64decode(value)
        aes_value = decrypt_with_rsa(private_key, encrypted_aes_value)
        decrypted_value = decrypt_data(aes_value)
        if isinstance(decrypted_value, bytes):
            decrypted_value = decrypted_value.decode('utf-8')
        decrypted_dict[key] = decrypted_value
    # index of tables

    return decrypted_dict


# change password
# warning: mentions the user required to change the password
@app.route('/warning', methods=['GET', 'POST'])
def warning():
    return render_template('warning.html', type=session.get('type'), username=session.get('username'))


# change password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    # Check if the user is logged in as a patient or doctor
    if session.get('type') in ['patient', 'doctor']:
        if request.method == 'POST':
            # Retrieve password and confirm password from form submission
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            # Validate password and confirm password
            username = session.get('username')
            # valid, message = validate_password(username, password, confirm_password)
            valid = True
            message = '1'
            if not valid:
                # If passwords are not valid, render the change_password template with an error message
                return render_template('change_password.html', type=session.get('type'),
                                       username=session.get('username'), error=message)
            else:
                # If passwords are valid, update session variable for password and redirect to verify_robot endpoint
                session['password'] = encrypt_data(password)
                session['page'] = 'change_password'
                return redirect(url_for('verify_robot'))

        # Render the change_password template for GET requests
        return render_template('change_password.html', type=session.get('type'), username=session.get('username'))
    else:
        # If a user is not authorized, render sorry.html template with an appropriate message
        return render_template('sorry.html', type=session.get('type'))



# Doctor page route
@app.route('/doctor_page', methods=['GET', 'POST'])
def doctor_page():
    if session.get('type') == 'doctor':
        response = requests.post('http://127.0.0.1:5001/',
                                 json={'page': 'doctor_page'})
        # Check the response from the server
        if response.status_code == 205:
            data = response.json()  # Extract JSON data from response
            decrypt_file_rsa(data['file'])
            return render_template('download.html', type=session.get('type'))
        else:
            return render_template('download.html', message='Sorry, error happened please try again', type=session.get('type'))
    else:
        return render_template('sorry.html', type=session.get('type'))

# Decrypt and save the file
def decrypt_file_rsa(encrypted_data):
    #encrypted_aes = base64.b64decode(encrypted_data)
    decoded_encrypted_data = [base64.b64decode(chunk.encode('utf-8')) for chunk in encrypted_data]
    data = decrypt_message(private_key, decoded_encrypted_data)

    with open("System_activity.txt", "wb") as System_activity_file:
        System_activity_file.write(data)

# Download file route
@app.route('/download')
def download_file():
    # Provide the path to the file you want to download
    file_path = 'System_activity.txt'

    # Send the file as an attachment for download
    return send_file(file_path, as_attachment=True)



if __name__ == '__main__':
    app.run(debug=True)
