import sqlite3
from encryption_AES import encrypt_data, decrypt_data


# Connect to SQLite database
def connect_database():
    return sqlite3.connect('database_username.db')


# Insert encrypted data into database
def insert_data_patient(conn, data, email):
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO patients (name, email) VALUES (?, ?)''', (data, email))
    conn.commit()


def insert_data_doctor(conn, data, email):
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO doctors (name, email) VALUES (?, ?)''', (data, email))
    conn.commit()


# Search for encrypted data in a database
def search_data_patient(conn, data):
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM patients WHERE name = ?''', (data,))
    row = cursor.fetchone()
    return row is not None


def search_data_doctor(conn, data):
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM doctors WHERE name = ?''', (data,))
    row = cursor.fetchone()
    return row is not None


def search_email_patient(data):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM patients WHERE name = ?''', (data,))
    row = cursor.fetchone()
    conn.close()
    if row is not None:
        email = row[2]
        return email
    else:
        return None

def search_email(data):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM patients WHERE email = ?''', (data,))
    row = cursor.fetchone()
    conn.close()
    if row is not None:
        return True
    else:
        return False
def search_email_doctor(data):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM doctors WHERE name = ?''', (data,))
    row = cursor.fetchone()
    conn.close()
    if row is not None:
        email = row[2]
        return email
    else:
        return None



# Create database tables
def create_tables():
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS doctors (
                        id INTEGER PRIMARY KEY,
                        name TEXT,
                        email TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS patients (
                        id INTEGER PRIMARY KEY,
                        name TEXT,
                        email TEXT
                    )''')
    conn.close()


# Delete all records from a table
def clear_table(table_name):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {table_name}")
    conn.commit()
    conn.close()


# Truncate a table (remove all records but keep the table structure)
def truncate_table(table_name):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(f"TRUNCATE TABLE {table_name}")
    conn.commit()
    conn.close()


# Drop a table (remove both records and the table structure)
def drop_table(table_name):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
    conn.commit()
    conn.close()


# Example usage
def username_database(type, function, encrypted_data, email):
    create_tables()  # Create tables if not exist

    conn = connect_database()

    if type == 'doctor' and function == 'insert':
        insert_data_doctor(conn, encrypted_data, email)
    elif type == 'patient' and function == 'insert':
        insert_data_patient(conn, encrypted_data, email)
    elif type == 'doctor' and function == 'search':
        found = search_data_doctor(conn, encrypted_data)
        if found:
            print("Data found in the database!")
            return True
        else:
            print("Data not found in the database!")
            return False
    elif type == 'patient' and function == 'search':
        found = search_data_patient(conn, encrypted_data)
        if found:
            print("Data found in the database!")
            return True
        else:
            print("Data not found in the database!")
            return False
    elif type == 'doctor' and function == 'clean':
        cursor = conn.cursor()
        cursor.execute('''DELETE FROM doctors''')
        conn.commit()
        print("All data from doctors table deleted.")
    elif type == 'patient' and function == 'clean':
        cursor = conn.cursor()
        cursor.execute('''DELETE FROM patients''')
        conn.commit()
        print("All data from patients table deleted.")

    conn.close()


# Example usage
if __name__ == '__main__':

    create_tables()
    encrypted_data = encrypt_data('Dr.TI')
    encrypted_email = encrypt_data('dragon@gmail.com')
    print(username_database('doctor', 'insert', encrypted_data, encrypted_email))
    print(search_email_doctor(encrypted_data))



