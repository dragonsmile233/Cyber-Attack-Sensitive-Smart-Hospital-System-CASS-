import sqlite3
from datetime import datetime
from encryption_AES import encrypt_data,decrypt_data

# Connect to SQLite database
def connect_database():
    return sqlite3.connect('database_user_email.db')

# Insert encrypted data into database
def insert_email(email):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO user_email (email) VALUES (?)''', (email,))
    conn.commit()
    conn.close()

# Insert PIN and receive time into database
def insert_pin(pin, email):
    conn = connect_database()
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''UPDATE user_email SET pin=?, receive_time=? WHERE email=?''', (pin, current_time, email))
    conn.commit()
    conn.close()

# Search for email data in the database
def search_email_data(email):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM user_email WHERE email = ?''', (email,))
    row = cursor.fetchone()
    conn.close()
    return row

# Create database tables
def create_tables():
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_email (
                                id INTEGER PRIMARY KEY,
                                email TEXT,
                                pin TEXT,
                                receive_time TEXT
                            )''')
    conn.close()

# Example usage
if __name__ == '__main__':
    create_tables()  # Create tables if not exist

    email = 'dragonsmile233@gmail.com'
    pin = '123'  # Replace with actual password
    encrypted_email = encrypt_data(email)
    encrypted_pin = encrypt_data(pin)

    # Insert encrypted email into database
    #insert_email(encrypted_email)

    # Connect to the database and insert PIN and receive time

    #insert_pin(encrypted_pin, encrypted_email)


    # Search for email data in the database

    row = search_email_data(encrypted_email)

    if row:
        password = row[2]
        message = encrypt_data('Password:')
        combined_message = message + password
        decrypted_pin= encrypt_data('Password:070979')
        receive_time = row[3]
        print(combined_message,decrypted_pin)
    else:
        print('No such')
