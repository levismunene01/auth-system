from flask import Flask


from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from .config import Config




db = SQLAlchemy()
mail = Mail()
login_manager = LoginManager()
jwt = JWTManager()



def create_app():
    app = Flask(__name__)
    app.config.from_object(config)

    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)


    from app.routes.auth_routes import auth_bp
    from app.routes.admin_routes import admin_bp


    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)




    return app


