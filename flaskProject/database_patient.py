import sqlite3
from encryption_AES import encrypt_data, decrypt_data  # Assuming you have defined these functions elsewhere
import base64
from encryption_AES import encrypt_data, decrypt_data


# Connect to SQLite database
def connect_database():
    return sqlite3.connect('database_patient.db')


def create_table():
    """Create patients table if it does not exist."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patients (
            PatientID INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT ,
            DateOfBirth TEXT,
            Gender TEXT ,
            Address TEXT,
            Phone TEXT,
            MedicalRecordNumber TEXT ,
            Allergies TEXT,
            CurrentMedications TEXT,
            PastMedicalConditions TEXT,
            FamilyMedicalHistory TEXT
        )
    ''')
    conn.commit()
    conn.close()


# Insert encrypted data into database
def update_patient_data(name, dob, gender, address, phone, medical_record_number, allergies, current_medications,
                        past_medical_conditions, family_medical_history):
    conn = connect_database()
    cursor = conn.cursor()

    cursor.execute(
        '''UPDATE patients SET DateOfBirth=?, Gender=?, Address=?, Phone=?, MedicalRecordNumber=?, Allergies=?, CurrentMedications=?, PastMedicalConditions=?, FamilyMedicalHistory=? WHERE Name=?''',
        (dob, gender, address, phone, medical_record_number, allergies, current_medications,
         past_medical_conditions, family_medical_history, name,))
    conn.commit()
    conn.close()


def insert_patient_usename(name):
    dob = encrypt_data('NONE')
    gender = encrypt_data('NONE')
    address = encrypt_data('NONE')
    phone = encrypt_data('NONE')
    medical_record_number = encrypt_data('NONE')
    allergies = encrypt_data('NONE')
    current_medications = encrypt_data('NONE')
    past_medical_conditions = encrypt_data('NONE')
    family_medical_history = encrypt_data('NONE')
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO Patients (Name, DateOfBirth, Gender, Address, Phone, MedicalRecordNumber, Allergies, CurrentMedications, PastMedicalConditions, FamilyMedicalHistory) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (name, dob, gender, address, phone, medical_record_number, allergies, current_medications,
         past_medical_conditions, family_medical_history))
    conn.commit()
    conn.close()

# Search data by username and store type in a dictionary
def search_data_patient(username):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM Patients WHERE name = ?''', (username,))
    row = cursor.fetchone()
    conn.commit()
    conn.close()
    if row is not None:
        patient_detail = {
            'Type': encrypt_data('patient'),
            'Name': row[1],  # Assuming name is stored in the second column
            'Date Of Birth': row[2],  # Assuming date of birth is stored in the third column
            'Gender': row[3],
            'Address': row[4],
            'Phone': row[5],
            'Medical Record Number': row[6],
            'Allergies': row[7],
            'Current Medications': row[8],
            'Past Medical Conditions': row[9],
            'Family Medical History': row[10]
        }
        return patient_detail
    else:
        return None

def decrypt_dictionary_values(dictionary):
    decrypted_dict = {}
    for key, value in dictionary.items():
        decrypted_value = decrypt_data(value)  # Decrypt the value
        decrypted_dict[key] = decrypted_value  # Store decrypted value in new dictionary
    return decrypted_dict

# Example usage
if __name__ == '__main__':
    create_table()
    if __name__ == '__main__':
        create_table()
        update_patient_data(encrypt_data('TIANYI'), encrypt_data('1980-01-01'), encrypt_data('Male'),
                            encrypt_data('123 Main Street, Anytown, USA'), encrypt_data('(555) 123-4567'),
                            encrypt_data('123456789'), encrypt_data('None'), encrypt_data('Aspirin, Lisinopril'),
                            encrypt_data('Hypertension, Diabetes'), encrypt_data('Heart disease, Cancer'))
        patent = search_data_patient(encrypt_data('TIANYI'))
        decrypted_patent = decrypt_dictionary_values(patent)
        print(decrypted_patent)
    insert_patient_usename(encrypt_data('X'))
    patent = search_data_patient(encrypt_data('X'))
    decrypt_dictionary_values(patent)
    print(decrypt_dictionary_values(patent))
