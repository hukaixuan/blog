import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
	SQLALCHEMY_COMMIT_ON_TEARDOWN = True
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	MAIL_SERVER = 'smtp.qq.com'
	MAIL_PORT = 25
	MAIL_USE_TLS = True
	MAIL_USERNAME = os.environ.get('QQ_MAIL_USERNAME')
	MAIL_PASSWORD = os.environ.get('QQ_MAIL_PASSWORD')
	MAIL_DEBUG = True
	FLASKY2_ADMIN = os.environ.get('FLASKY2_ADMIN')
	FLASKY2_POSTS_PER_PAGE = 15
	FLASKY2_COMMENTS_PER_PAGE = 10
	SQLALCHEMY_RECORD_QUERIES = True
	FLASKY2_SLOW_DB_QUERY_TIME = 0.05

	@staticmethod
	def init_app(app):
		pass

class DevelopmentConfig(Config):
	DEGUG = True
	SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///'+os.path.join(basedir, 'data-dev.sqlite')
	BOOTSTRAP_SERVE_LOCAL = True	# 开发时关闭 cdn开启本地bootstrap资源，方便没网时候开发

class TestingConfig(Config):
	TESTING = True
	SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///'+os.path.join(basedir, 'data-test.sqlite')
	BOOTSTRAP_SERVE_LOCAL = True	# 开发时关闭 cdn开启本地bootstrap资源，方便没网时候开发
	WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
	SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///'+os.path.join(basedir, 'data.sqlite')


config = {
	'development' : DevelopmentConfig,
	'testing' : TestingConfig,
	'production' : ProductionConfig,

	'default' : DevelopmentConfig
}













