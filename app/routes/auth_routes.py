


from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import User
from flask_jwt_extended import create_access_token




auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify(msg='Email already exists'), 400

    hashed_password = generate_password_hash(password)

    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify(msg='User registered successfully')




@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify(msg='Invalid credentials'), 401

    if not user.is_confirmed:
        return jsonify(msg='Please confirm your email first'), 403

    access_token = create_access_token(identity={
        'id': user.id,
        'email': user.email,
        'role': user.role
    })




    return jsonify(access_token=access_token)
