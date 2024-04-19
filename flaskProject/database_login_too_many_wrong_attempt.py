import sqlite3
from datetime import datetime, timedelta

import sqlite3
from datetime import datetime, timedelta

def connect_database():
    return sqlite3.connect('database_error_attempts.db')

def create_tables():
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS login (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        login_attempts INTEGER DEFAULT 0,
                        last_entry_time TEXT
                    )''')
    conn.close()

def reset_attempts_after_30_minutes(conn,username):
    cursor = conn.cursor()
    cursor.execute('''SELECT last_entry_time FROM login WHERE username=?''', (username,))
    last_entry_time_str = cursor.fetchone()
    if last_entry_time_str:
        last_entry_time = datetime.strptime(last_entry_time_str[0], '%Y-%m-%d %H:%M:%S')
        if datetime.now() - last_entry_time > timedelta(minutes=30):
            # Reset login attempts
            cursor.execute('''UPDATE login SET login_attempts=0 WHERE username=?''', (username,))
            conn.commit()

def check_and_update_login_attempts(username, status_code):
    conn = connect_database()
    cursor = conn.cursor()
    if status_code == 200:
        cursor.execute('''UPDATE login SET login_attempts=0 WHERE username=?''', (username,))
        cursor.execute('''DELETE FROM login WHERE username=?''', (username,))
        conn.commit()
    else:
        if not search_username(conn,username):
            cursor.execute('''INSERT INTO login (username, login_attempts) VALUES (?, ?)''', (username, 1))
            record_last_entry_time(conn,username)
            conn.commit()
        else:
            cursor.execute('''UPDATE login SET login_attempts=login_attempts+1 WHERE username=?''', (username,))
            record_last_entry_time(conn,username)
            conn.commit()
    conn.close()

def search_username(conn,username):
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM login WHERE username = ?''', (username,))
    row = cursor.fetchone()
    if row is not None:
        return True
    else:
        return False

def record_last_entry_time(conn,username):
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''UPDATE login SET last_entry_time=? WHERE username=?''', (current_time, username))
    conn.commit()

def search_last_entry_time(username):
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('''SELECT last_entry_time FROM login WHERE username=?''', (username,))
    last_entry_time_str = cursor.fetchone()
    conn.close()
    if last_entry_time_str:
        return last_entry_time_str[0]
    else:
        return None

def search_attempts(username):
    conn = connect_database()
    cursor = conn.cursor()
    reset_attempts_after_30_minutes(conn, username)
    cursor.execute('''SELECT login_attempts FROM login WHERE username=?''', (username,))
    last_entry_time_str = cursor.fetchone()
    conn.close()
    if last_entry_time_str:
        return last_entry_time_str[0]
    else:
        return 0

if __name__ == '__main__':
    create_tables()
    username = 'example_user'
    status_code = 400  # Example status code (401: Unauthorized)
    attempts = search_attempts(username)
    check_and_update_login_attempts(username, status_code)


    last_entry_time = search_last_entry_time(username)
    current_time = datetime.now()

    last_entry_time = datetime.strptime(last_entry_time, '%Y-%m-%d %H:%M:%S')
    remaining_seconds = (last_entry_time + timedelta(minutes=30) - current_time).total_seconds()

    # 将总秒数转换为分钟

    # 将总秒数转换为分钟
    remaining_minutes, remaining_seconds = divmod(remaining_seconds, 60)

    error_message = "Remaining time:", "{:.0f} minutes {:.0f} seconds".format(remaining_minutes,
                                                                              remaining_seconds)
    print("Login attempts:", attempts)
    if last_entry_time:
        print(error_message)
    else:
        print("Last entry time not available.")
