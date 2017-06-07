from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_moment import Moment
from config import config	# 这是app package的init，所以与config.py同级
from flask_login import LoginManager
from flask_pagedown import PageDown


# create them uninitialized
bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
login_manager = LoginManager()
pagedown = PageDown()

login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'


# factory function
def create_app(config_name):
	app = Flask(__name__)
	app.config.from_object(config[config_name])	# 从config.py根据传入的config_name选取对应的class进行配置
	config[config_name].init_app(app)	#init_app是干啥的？？？啥作用？

	bootstrap.init_app(app)
	mail.init_app(app)
	moment.init_app(app)
	db.init_app(app)
	login_manager.init_app(app)
	pagedown.init_app(app)

	from .main import main as main_blueprint
	app.register_blueprint(main_blueprint)

	from .auth import auth as auth_blueprint
	app.register_blueprint(auth_blueprint, url_prefix='/auth')

	from .api_1_0 import api as api_blueprint
	app.register_blueprint(api_blueprint, url_prefix='/api/v1.0')

	return app

