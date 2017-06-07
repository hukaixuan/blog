from flask import Flask, request, make_response, redirect, abort, render_template, session, url_for, flash

from flask_script import Manager, Server, Shell
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm					# 从 flask——wtf import FlaskForm基类
from wtforms import StringField, SubmitField	# 从 wtforms import 各种 Field
from wtforms.validators import Required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_mail import Message, Mail


# from datetime import datetime
import os
from threading import Thread

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'hello world'
app.config['BOOTSTRAP_SERVE_LOCAL'] = True	#启用本地bootstrap，禁用cdn
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.qq.com'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('QQ_MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('QQ_MAIL_PASSWORD')	# 不是邮箱的登录密码，是特定的授权码！
app.config['MAIL_DEBUG'] = True
app.config['FLASKY2_ADMIN'] = os.environ.get('FLASKY2_ADMIN')


manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bootstrap = Bootstrap(app)
moment = Moment(app)
mail = Mail(app)

class NameForm(FlaskForm):				# 自定义一个Form类
	name = StringField("what's your name", validators=[Required()])
	submit = SubmitField("submit")

class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(64), unique = True)
	users = db.relationship('User', backref = 'role')

	def __repr__(self):
		return '<Role %r>' %self.name


class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(64), unique = True, index = True)
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

	def __repr__(self):
		return '<User %r>' %self.username


@app.route('/', methods=['GET', 'POST'])
def index():
	form = NameForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username = form.name.data).first()
		if user is None:
			flash('您是新用户，已自动为您注册')
			user = User(username = form.name.data)
			db.session.add(user)
			session['known'] = False
			if app.config['FLASKY2_ADMIN']:
				send_mail(app.config['FLASKY2_ADMIN'], '有新用户注册', 'mail/new_user', user=user)
		else:
			session['known'] = True
		session['name'] = form.name.data
		form.name.data = ''
		return redirect(url_for('index'))
	return render_template('index.html', name = session.get('name'), form = form, known = session.get('known', False))

@app.route('/test')
def test():
	form = NameForm()
	return render_template('test.html', form = NameForm())
	

@app.route('/user/<path:name>')
def hello(name):
	return render_template('user.html', name=name)

@app.route('/redirect')
def redirect_to():
	return redirect('http://www.example.com')

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
	return render_template('500.html'), 500

def test():
	msg = Message()

def make_shell_context():
	return dict(app = app, db = db, User = User, Role = Role)


def send_async_mail(app, msg):
	with app.app_context():
		mail.send(msg)

def send_mail(to, subject, template, **kwargs):
	msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to])
	msg.body = render_template(template+'.txt', **kwargs)
	msg.html = render_template(template+'.html', **kwargs)
	thr = Thread(target=send_async_mail, args=[app, msg])
	thr.start()
	return thr


manager.add_command("runserver", Server(use_debugger = True))
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command("db", MigrateCommand)

if __name__ == '__main__':
	manager.run()
	# app.run(debug = True)

