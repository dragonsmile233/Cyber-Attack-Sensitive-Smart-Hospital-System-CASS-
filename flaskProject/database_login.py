import sqlite3
from encryption_AES import encrypt_data, decrypt_data
import base64
from datetime import datetime, timedelta
from database_username import drop_table


# Connect to SQLite database
def connect_database(type):
    if type == 'patient':
        return sqlite3.connect('database_patient_login.db')
    elif type == 'doctor':
        return sqlite3.connect('database_doctor_login.db')


# Insert encrypted data into database
def insert_data_patient(conn, username, password):
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('''INSERT INTO patients (username, password,modified_time) VALUES (?, ?, ?)''',
                   (username, password, current_time))
    conn.commit()


def insert_data_doctor(conn, username, password):
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('''INSERT INTO doctors (username, password,modified_time) VALUES (?, ?, ?)''',
                   (username, password, current_time))
    conn.commit()


# Search for encrypted data in a database
def search_data_patient(conn, username, password):
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM patients WHERE username = ? AND password = ?''', (username, password))
    row = cursor.fetchone()
    return row is not None


def search_data_patient_password(username):
    conn = connect_database('patient')
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM patients WHERE username = ? ''', (username,))
    row = cursor.fetchone()
    if row is not None:
        return row[2], row[3]
    else:
        return None


def search_data_doctor_password(username):
    conn = connect_database('doctor')
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM doctors WHERE username = ? ''', (username,))
    row = cursor.fetchone()
    if row is not None:
        return row[2], row[3]
    else:
        return None


def search_data_doctor(conn, username, password):
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM doctors WHERE username = ? AND password = ?''', (username, password))
    row = cursor.fetchone()
    return row is not None


# Create database tables
def create_tables():
    # Create tables for both patient and doctor databases
    conn_patient = connect_database('patient')
    cursor_patient = conn_patient.cursor()
    cursor_patient.execute('''CREATE TABLE IF NOT EXISTS patients (
                                id INTEGER PRIMARY KEY,
                                username TEXT,
                                password TEXT,
                                modified_time TEXT
                            )''')

    conn_patient.close()

    conn_doctor = connect_database('doctor')
    cursor_doctor = conn_doctor.cursor()
    cursor_doctor.execute('''CREATE TABLE IF NOT EXISTS doctors (
                                id INTEGER PRIMARY KEY,
                                username TEXT,
                                password TEXT,
                                modified_time TEXT
                            )''')

    conn_doctor.close()


# Example usage
def login_database(type, function, username, password):
    create_tables()  # Create tables if not exist

    # Connect to the appropriate database based on the type
    conn = connect_database(type)

    if type == 'doctor' and function == 'insert':
        insert_data_doctor(conn, username, password)
    elif type == 'patient' and function == 'insert':
        insert_data_patient(conn, username, password)
    elif type == 'doctor' and function == 'search':
        found = search_data_doctor(conn, username, password)
        if found:
            print("Data found in the database!")
            return True
        else:
            print("Data not found in the database!")
            return False
    elif type == 'patient' and function == 'search':
        found = search_data_patient(conn, username, password)
        if found:
            print("Data found in the database!")
            return True
        else:
            print("Data not found in the database!")
            return False
    conn.close()


def change_user_password(type, username, password):
    conn = connect_database(type)
    cursor = conn.cursor()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if type == 'patient':
        cursor.execute('''UPDATE patients SET password=?, modified_time=? WHERE username=?''',
                       (password, current_time, username))
    elif type == 'doctor':
        cursor.execute('''UPDATE doctors SET password=?, modified_time=? WHERE username=?''',
                       (password, current_time, username))
    conn.commit()
    conn.close()


def change_time(type, username, time):
    conn = connect_database(type)
    cursor = conn.cursor()
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    if type == 'patient':
        cursor.execute('''UPDATE patients SET modified_time=? WHERE username=?''',
                       (current_time, username))
    elif type == 'doctor':
        cursor.execute('''UPDATE doctors SET modified_time=? WHERE username=?''',
                       (current_time, username))
    conn.commit()
    conn.close()


def drop_table_patient(table_name):
    conn = connect_database('patient')
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
    conn.commit()
    conn.close()


def drop_table_doctor(table_name):
    conn = connect_database('doctor')
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
    conn.commit()
    conn.close()


# Example usage
if __name__ == '__main__':
    create_tables()

    username = 'DR.TIANYI'
    password = 'password123'  # Replace with actual password
    encrypted_username = encrypt_data(username)
    encrypted_password = encrypt_data(password)
    time = datetime.now() - timedelta(days=40)
    login_database('doctor','insert',encrypted_username,encrypted_password)
    change_time('patient', encrypted_username, time)
    data, date = search_data_patient_password(encrypted_username)
    print(decrypt_data(data), date)
