# Import Flask and other necessary modules
from flask import Flask, render_template, request, redirect, url_for
from encryption_AES import encrypt_data, decrypt_data
from email_database import search_email_data

app3 = Flask(__name__)


# Define routes
@app3.route('/', methods=['GET', 'POST'])
def user_email():
    if request.method == 'POST':
        user_email_input = request.form['email']
        encrypted_data = encrypt_data(user_email_input)
        if search_email_data(encrypted_data) is not None:
            return redirect(url_for('email_page', email=user_email_input))
        else:
            error_message = 'Invalid Email'
            return render_template('user_email.html', error=error_message)
    return render_template('user_email.html')


@app3.route('/email-page/<email>', methods=['GET', 'POST'])
def email_page(email):
    encrypted_data = encrypt_data(email)
    data = search_email_data(encrypted_data)
    if data:
        pin = decrypt_data(data[2])
        receive_time = data[3]
        return render_template('email_page.html', email=decrypt_data(encrypted_data), pin=pin,
                               receive_time=receive_time)
    else:
        error_message = 'Email not found or data incomplete'
        return render_template('user_email.html', error=error_message)


if __name__ == '__main__':
    app3.run(debug=True, port=5002)
