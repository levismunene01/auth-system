from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_mail import Message
from app import db, mail
from app.models import User
from app.utils.token import generate_confirmation_token, confirm_token
from datetime import timedelta

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['POST'])
def register():
    # Input validation
    data = request.get_json()  # Changed from .json to .get_json()
    if not data:
        return jsonify(msg='No JSON data received'), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Check for missing fields
    if not all([username, email, password]):
        return jsonify(msg='Missing required fields'), 400

    # Validate email format (basic check)
    if '@' not in email or '.' not in email:
        return jsonify(msg='Invalid email format'), 400

    # Check if user exists
    if User.query.filter((User.email == email) | (User.username == username)).first():
        return jsonify(msg='Email or username already exists'), 409  # 409 Conflict

    try:
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            is_confirmed=False
        )
        db.session.add(new_user)
        db.session.commit()

        # Generate confirmation token and URL
        token = generate_confirmation_token(email)
        confirm_url = f"{request.host_url}auth/confirm/{token}"  # Dynamic host URL
        
        # Send confirmation email
        msg = Message(
            'Confirm Your Email',
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
            recipients=[email]
        )
        msg.body = f'Click the link to confirm your email: {confirm_url}'
        mail.send(msg)

        return jsonify({
            'msg': 'Registration successful. Check your email to confirm.',
            'user_id': new_user.id
        }), 201  # 201 Created

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Registration error: {str(e)}')
        return jsonify(msg='Registration failed'), 500

@auth_bp.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = confirm_token(token)
        if not email:
            return jsonify(msg='Confirmation link is invalid or expired'), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(msg='User not found'), 404

        if user.is_confirmed:
            return jsonify(msg='Account already confirmed'), 200

        user.is_confirmed = True
        db.session.commit()
        
        # Automatically log in the user after confirmation
        access_token = create_access_token(
            identity={
                'id': user.id,
                'email': user.email,
                'role': user.role
            },
            expires_delta=timedelta(days=7)
        )
        
        return jsonify({
            'msg': 'Email confirmed successfully!',
            'access_token': access_token
        }), 200

    except Exception as e:
        current_app.logger.error(f'Confirmation error: {str(e)}')
        return jsonify(msg='Confirmation failed'), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify(msg='No JSON data received'), 400

    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify(msg='Missing email or password'), 400

    user = User.query.filter_by(email=email).first()
    
    # Security: Use constant time comparison
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify(msg='Invalid credentials'), 401

    if not user.is_confirmed:
        return jsonify(msg='Please confirm your email first'), 403

    # Create JWT token with expiration
    access_token = create_access_token(
        identity={
            'id': user.id,
            'email': user.email,
            'role': user.role
        },
        expires_delta=timedelta(days=1)  # Shorter expiration for login tokens
    )

    return jsonify({
        'access_token': access_token,
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    }), 200