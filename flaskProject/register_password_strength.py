import re


def validate_password(username, password,confirm_password):
    # Check if the password contains at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'

    # Check if the password contains at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'

    # Check if the password contains at least one digit
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit'

    # Check if the password contains at least one special character
    if not re.search(r'[!@#$%^&*()-_=+{};:,.<>?\\|~]', password):
        return False, 'Password must contain at least one special character'

    if username.lower() in password.lower():
        error = 'Password cannot contain your username'
        return False, error
    # Check if the password meets the minimum length requirement
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long'

    if password != confirm_password:
        error = 'Passwords do not match'
        return False,error
    return True, 'Password meets the strength requirements'


# Example usage:
password = ('Paaaaii1')
valid, message = validate_password('iii',password,'a')
print(message)
