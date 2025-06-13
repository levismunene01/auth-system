
from app.utils.email_utils import send_confirmation_email

# app/utils/email_utils.py
from flask_mail import Message
from flask import url_for
from app import mail

def send_confirmation_email(user, email):
    token = user.generate_confirmation_token()
    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
    subject = 'Please confirm your email'
    body = f'Hi {user.username}, click the link to confirm your email: {confirm_url}'

    msg = Message(subject=subject, recipients=[email], body=body)
    mail.send(msg)
