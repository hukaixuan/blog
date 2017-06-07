from flask import render_template, redirect, request, flash, url_for
from . import auth		# blueprint
from flask_login import login_required, login_user, logout_user, current_user
from .forms import LoginForm, RegistrationForm, UpdatePasswordForm, PasswordResetRequestForm, PasswordResetForm
from ..models import User
from .. import db
from ..email import send_email

@auth.before_app_request
def before_request():
	if current_user.is_authenticated:
		current_user.ping()		# 更新用户最后登录时间
		if not current_user.confirmed \
				and request.endpoint \
				and request.endpoint[:5] != 'auth.' \
				and request.endpoint != 'static':	#当前用户已登录，未确认邮件，并且请求的不是auth路径下的内容
			return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
	if current_user.is_anonymous or current_user.confirmed:		#当前用户是匿名用户或已确认用户
		return redirect(url_for('main.index'))
	return render_template('auth/unconfirmed.html')

@auth.route('/login', methods=['GET','POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.args.get('next') or url_for('main.index'))
		flash('Invalid username or password.')
	return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data, username=form.username.data, 
					password=form.password.data)
		db.session.add(user)
		db.session.commit()		# 要立即提交数据库，因为后面的操作需要提交后自动生成的 id 字段
		token = user.generate_confirmation_token()
		send_email(user.email, 'Confirm your account', 'auth/email/confirm', user=user, token=token)
		flash('a confirmation has been send to you by email')
		return redirect(url_for('auth.login'))
	return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
	if current_user.confirmed:
		return redirect(url_for('main.index'))
	elif current_user.confirm(token):
		flash('you have confirmed your token')


	else:
		flash('The confirmation link is invalid or expired')
	return redirect(url_for('main.index'))


@auth.route('/confirm')		# 再次发送邮件确认
@login_required
def resend_confirmation():
	token = current_user.generate_confirmation_token()
	send_email(current_user.email, 'Confirm your account', 'auth/email/confirm', user=current_user, token=token)
	flash('a new confirmation has been send to you by email')
	return redirect(url_for('main.index'))

@auth.route('/password/update', methods=['GET','POST'])
@login_required
def update_password():
	"""更改密码(已知旧密码)"""
	form = UpdatePasswordForm()
	if form.validate_on_submit():
		if not current_user.verify_password(form.old_password.data):
			flash('your old password is not right! Please try again!')
			return redirect(url_for('.update_password'))
		if current_user.update_password(form.new_password.data):	# 如果更新密码成功
			logout_user()			# 登出现有用户，重新登录
			flash('you have changed your password, please login')
			return redirect(url_for('.login'))
		else:
			flash('failed to update your password, please try again')
	return render_template('auth/password/update.html', form = form)

@auth.route('/password/reset', methods=['GET', 'POST'])
def reset_password_request():
	"""重置密码(忘记密码)--填写接受link的邮箱"""
	form = PasswordResetRequestForm()
	if form.validate_on_submit():
		if form.email.data:
			to_email = form.email.data
			user = User.query.filter_by(email=to_email).first()
			if user:
				token = user.generate_confirmation_token()
				send_email(to_email, 'reset your password', 'auth/email/reset_password', user=user, token=token)
				flash('the link has been send to your inbox')
	return render_template('auth/password/reset.html', form=form)

@auth.route('/password/change/<id>/<token>', methods=['GET', 'POST'])
def reset_password(id, token):
	"""通过邮箱token更改密码--填写更改密码的表格"""
	form = PasswordResetForm()
	user = User.query.filter_by(id=id).first()
	if not user or not user.confirm(token):
		return redirect(url_for('.reset_password_request'))
	if form.validate_on_submit():
		user.password = form.new_password.data
		db.session.add(user)
		flash('you have changed your password, please login')
		return redirect(url_for('.login'))
	return render_template('auth/password/reset.html', form=form)



@auth.route('/secret')
@login_required
def secret():
	return 'Only authenticated users are allowed!'










