




# app/utils/email_utils.py

from flask_mail import Message
from flask import url_for
from app import mail

def send_confirmation_email(user, email):
    token = user.generate_confirmation_token()
    confirm_url = url_for('auth.confirm_email', token=token, _external=True)

    msg = Message('Confirm Your Email',
                  sender='your_email@gmail.com',
                  recipients=[email])
    msg.body = f'Click the link to confirm your email: {confirm_url}'
    mail.send(msg)
