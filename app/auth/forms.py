from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SubmitField
from wtforms.validators import Required, Email, Length, Regexp, EqualTo
from wtforms import ValidationError

from app.models import User


class LoginForm(FlaskForm):
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	username = StringField('UserName', validators=[Required(), Length(1,64),
										Regexp('^[a-zA-Z][a-zA-Z0-9_.]*$',0,'The name is invalid')])
	password = PasswordField('Password', validators=[Required(), EqualTo('password2', 'passwords must match')])
	password2 = PasswordField('Confirm Password', validators=[Required()])
	submit = SubmitField('Register')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in use')

class UpdatePasswordForm(FlaskForm):
	old_password = PasswordField('Old password', validators=[Required()])
	new_password = PasswordField('New password', validators=[Required(), EqualTo('new_password2', 'passwords must match')])
	new_password2 = PasswordField('Confirm New password', validators=[Required()])
	submit = SubmitField('Submit')


class PasswordResetRequestForm(FlaskForm):
	"""邮件发送表单、用来发送发送重置密码链接"""
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	submit = SubmitField('Send me a email to change the password')


class PasswordResetForm(FlaskForm):
	"""修改密码表单"""
	new_password = PasswordField('New password', validators=[Required(), EqualTo('new_password2', 'passwords must match')])
	new_password2 = PasswordField('Confirm New password', validators=[Required()])
	submit = SubmitField('Submit')

	def validate_email(self, field):
		if User.query.filter_by(email = field.data).first():
			raise ValidationError('Unknown email address')










