from datetime import datetime, timedelta

from flask import Flask, request, render_template
import base64
from encryption_AES import encrypt_data, decrypt_data
from database_login import login_database, search_data_patient_password, search_data_doctor_password, \
    change_user_password
from email_database import insert_pin
from encryption_RSA_server import load_private_key, decrypt_with_rsa
from database_patient import insert_patient_usename, search_data_patient
from encryption_RSA_client import load_public_key, encrypt_with_rsa
from encryption_RSA_file import encrypt_message
app2 = Flask(__name__)
private_key = load_private_key("private_key.pem")
public_key = load_public_key("public_key_client.pem")


# Status codes
# success:
# 200: login successful for patient
# 201: register successful
# 202: forget password successful
# 203: patient home successful
# 204: change password successful
# warning:
# 300: require change password
# error:
# 400: login failure
# 401: register failure
# 402: same password(change password failure)


# Functions related to log in part
def login(username, password):
    is_correct = login_database('patient', 'search', username, password)
    if is_correct:
        stored_password, last_password_change_time = search_data_patient_password(username)
        current_time = datetime.now()
        last_password_change_time = datetime.strptime(last_password_change_time, "%Y-%m-%d %H:%M:%S")
        if current_time < last_password_change_time + timedelta(days=30):
            return {'message': 'Login successful.', 'page': 'home'}, 200
        else:
            encrypted_value = encrypt_with_rsa(public_key, stored_password)
            encoded_value = base64.b64encode(encrypted_value).decode('utf-8')
            data = {'password': encoded_value, 'time': last_password_change_time}
            return data, 300
    else:
        return {'error': 'Incorrect username or password.'}, 400


def doctor(username, password):
    is_correct = login_database('doctor', 'search', username, password)
    if is_correct:
        stored_password, last_password_change_time = search_data_doctor_password(username)
        current_time = datetime.now()
        last_password_change_time = datetime.strptime(last_password_change_time, "%Y-%m-%d %H:%M:%S")
        if current_time < last_password_change_time + timedelta(days=30):
            return {'message': 'Login successful.', 'page': 'home'}, 200
        else:
            encrypted_value = encrypt_with_rsa(public_key, stored_password)
            encoded_value = base64.b64encode(encrypted_value).decode('utf-8')
            data = {'password': encoded_value, 'time': last_password_change_time}
            return data, 300
    else:
        return {'error': 'Incorrect username or password.'}, 400


def register(username, password):
    login_database('patient', 'insert', username, password)
    insert_patient_usename(username)
    is_correct = login_database('patient', 'search', username, password)
    print(is_correct)
    if is_correct:
        return {'message': 'Login successful.', 'page': 'home'}, 201
    else:
        return {'error': 'Error.'}, 401


def forget(username, email):
    password, time = search_data_patient_password(username)
    decoded_password = decrypt_data(password)
    message = 'Password:  ' + decoded_password
    encrypted_message = encrypt_data(message)
    insert_pin(encrypted_message, email)
    return {'message': 'Login successful.', 'page': 'home'}, 202


def patient_page(username):
    dictionary = search_data_patient(username)
    encrypted_message = encrypt_dictionary_values(dictionary)
    return encrypted_message, 203


def change_password(type, username, password):
    if type == 'patient':
        stored_password, last_password_change_time = search_data_patient_password(username)
        if password == stored_password:
            return {'error': 'same password'}, 402
        else:
            change_user_password(type, username, password)
            return {'message': ' successful.'}, 204

    elif type == 'doctor':
        stored_password, last_password_change_time = search_data_doctor_password(username)
        if password == stored_password:
            return {'error': 'same password'}, 402
        else:
            change_user_password(type, username, password)
            return {'message': ' successful.'}, 204


def encrypt_dictionary_values(dictionary):
    decrypted_dict = {}
    for key, value in dictionary.items():
        encrypted_value = encrypt_with_rsa(public_key, value)
        encoded_value = base64.b64encode(encrypted_value).decode('utf-8')
        decrypted_dict[key] = encoded_value  # Store decrypted value in new dictionary
    return decrypted_dict


def doctor_page():
    with open('packet.txt', 'rb') as file:
        data = file.read()
    print(data)
    encrypted_data = encrypt_message(public_key, data)
    encoded_encrypted_data = [base64.b64encode(chunk).decode('utf-8') for chunk in encrypted_data]
    # 发送加密后的文件到服务器
    return {'file': encoded_encrypted_data}, 205


# Server route
@app2.route('/', methods=['POST'])
def server():
    data = request.json
    page = data.get('page', '')
    if page == 'login':
        username = data.get('username', '')
        password = data.get('password', '')
        # Decode base64 encoded strings back to bytes objects
        encrypted_aes_username = base64.b64decode(username)
        encrypted_aes_password = base64.b64decode(password)
        encrypted_username = decrypt_with_rsa(private_key, encrypted_aes_username)
        encrypted_password = decrypt_with_rsa(private_key, encrypted_aes_password)
        return login(encrypted_username, encrypted_password)
    elif page == 'register':
        username = data.get('username', '')
        password = data.get('password', '')
        # Decode base64 encoded strings back to bytes objects
        encrypted_aes_username = base64.b64decode(username)
        encrypted_aes_password = base64.b64decode(password)
        encrypted_username = decrypt_with_rsa(private_key, encrypted_aes_username)
        encrypted_password = decrypt_with_rsa(private_key, encrypted_aes_password)
        return register(encrypted_username, encrypted_password)
    elif page == 'doctor':
        username = data.get('username', '')
        password = data.get('password', '')
        # Decode base64 encoded strings back to bytes objects
        encrypted_aes_username = base64.b64decode(username)
        encrypted_aes_password = base64.b64decode(password)
        encrypted_username = decrypt_with_rsa(private_key, encrypted_aes_username)
        encrypted_password = decrypt_with_rsa(private_key, encrypted_aes_password)
        return doctor(encrypted_username, encrypted_password)
    elif page == 'forget':
        username = data.get('username', '')
        email = data.get('email', '')
        encrypted_aes_username = base64.b64decode(username)
        encrypted_aes_email = base64.b64decode(email)
        encrypted_username = decrypt_with_rsa(private_key, encrypted_aes_username)
        encrypted_email = decrypt_with_rsa(private_key, encrypted_aes_email)
        return forget(encrypted_username, encrypted_email)
    elif page == 'patient_page':
        username = data.get('username', '')
        encrypted_aes_username = base64.b64decode(username)
        encrypted_username = decrypt_with_rsa(private_key, encrypted_aes_username)
        return patient_page(encrypted_username)
    elif page == 'change_password':
        type = data.get('type', '')
        username = data.get('username', '')
        password = data.get('password', '')
        encrypted_aes_username = base64.b64decode(username)
        encrypted_aes_password = base64.b64decode(password)
        encrypted_username = decrypt_with_rsa(private_key, encrypted_aes_username)
        encrypted_password = decrypt_with_rsa(private_key, encrypted_aes_password)
        return change_password(type, encrypted_username, encrypted_password)
    elif page == 'doctor_page':
        return doctor_page()
    else:
        return {'error': 'Invalid request.'}, 404


if __name__ == '__main__':
    app2.run(debug=True, port=5001)
