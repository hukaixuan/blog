from . import db	# package 'app' 在init中的 db
from werkzeug.security import generate_password_hash, check_password_hash
from . import login_manager
from flask_login import UserMixin, AnonymousUserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for
from markdown import markdown
import bleach
from .exceptions import ValidationError

from datetime import datetime
import hashlib

class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	default = db.Column(db.Boolean, default=False, index=True)		# 普通用户注册时设为TRUE
	permissions = db.Column(db.Integer)		# 拥有的权限
	users = db.relationship('User', backref='role', lazy='dynamic')

	@staticmethod
	def insert_roles():
		roles = {
			'User':(Permission.FOLLOW |
					Permission.COMMENT |
					Permission.WRITE_ARTICLES, True),
			'Monderator':  (Permission.FOLLOW | 
							Permission.COMMENT |
							Permission.WRITE_ARTICLES |
							Permission.MODERATE_COMMENTS, False),
			'Administrator': (0xff, False)
		}
		for r in roles:
			role = Role.query.filter_by(name=r).first()
			if role is None:
				role = Role(name=r)
				role.permissions = roles[r][0]
				role.default = roles[r][1]
				db.session.add(role)
		db.session.commit()		# 更新各用户角色对应的权限

	def __repr__(self):
		return '<Role %r>' % self.name

class Follow(db.Model):
	__tablename__ = 'follows'

	follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
							primary_key=True)
	followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
							primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(64), unique=True, index=True)
	username = db.Column(db.String(64), unique=True)
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	password_hash = db.Column(db.String(128))
	confirmed = db.Column(db.Boolean, default=False)
	name = db.Column(db.String(64))	# 真实姓名
	location = db.Column(db.String(64)) # 住址
	about_me = db.Column(db.Text())	# 个人简介
	member_since = db.Column(db.DateTime(), default=datetime.utcnow)	# note that missing the ()
	last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
	avatar_hash = db.Column(db.String(32))
	posts = db.relationship('Post', backref='author', lazy='dynamic')	# 发表的文章
	followed = db.relationship('Follow',
								foreign_keys=[Follow.follower_id],
								backref=db.backref('follower', lazy='joined'),
								lazy='dynamic',
								cascade='all, delete-orphan')
	followers = db.relationship('Follow',
								foreign_keys=[Follow.followed_id],
								backref=db.backref('followed', lazy='joined'),
								lazy='dynamic',
								cascade='all, delete-orphan')
	comments = db.relationship('Comment', backref='author', lazy='dynamic')

	def __init__(self, **kwargs):
		super(User, self).__init__(**kwargs)
		if self.role is None:
			if self.email == current_app.config['FLASKY2_ADMIN']:		# 根据预先设置的管理员邮箱判断如何设置权限
				self.role = Role.query.filter_by(permissions=0xff).first()
			if self.role is None:
				self.role = Role.query.filter_by(default=True).first()
		if self.email is not None and self.avatar_hash is None:
			self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()

	@property
	def password(self):
		raise AttributeError("password is not a readable attribute")

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		"""确认密码是否正确"""
		return check_password_hash(self.password_hash, password)

	def update_password(self, new_password):
		"""更新密码"""
		self.password = new_password
		db.session.add(self)
		return True

	def generate_confirmation_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'])
		return s.dumps({'confirm': self.id})

	def confirm(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return False
			# raise AttributeError('出错1')
		if data.get('confirm') != self.id:
			return False
			# raise AttributeError('出错2')
		self.confirmed = True
		db.session.add(self)
		return True

	def can(self, permissions):
		"""判断是否有此权限"""
		return self.role is not None and \
				(self.role.permissions & permissions) == permissions

	def is_administrator(self):
		return self.can(Permission.ADMINISTER)

	def ping(self):
		"""更新用户最后登录时间"""
		self.last_seen = datetime.utcnow()
		db.session.add(self)

	def follow(self, user):
		"""关注某人"""
		if not self.is_following(user):
			f = Follow(follower=self, followed=user)
			db.session.add(f)

	def unfollow(self, user):
		"""取消关注某人"""
		f = self.followed.filter_by(followed_id=user.id).first()
		if f:
			db.session.delete(f)

	def is_following(self, user):
		"""是否正在关注某人"""
		return self.followed.filter_by(
			followed_id=user.id).first() is not None

	def is_followed_by(self, user):
		"""是否被某人关注"""
		return self.followers.filter_by(
			follower_id=user.id).first() is not None

	@property		# define the function as a property,so it will act like a normal attribute
	def followed_posts(self):
		"""获取关注的用户发表的文章"""
		return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
				.filter(Follow.follower_id == self.id)	# 为啥是 == ????

	def gravatar(self, size=100, default='identicon', rating='g'):
		"""利用 www.gravatar.com/avatar 获取或产生随机头像"""
		if request.is_secure:
			url = 'https://secure.gravatar.com/avatar'
		else:
			url = 'http://www.gravatar.com/avatar'
		hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
		return '{url}/{hash}?s={size}&d={default}&r{rating}'.format(
						url=url, hash=hash, size=size, default=default, rating=rating)

	@staticmethod
	def generate_fake(count=100):
		"""填充随机测试数据"""
		from sqlalchemy.exc import IntegrityError
		from random import seed
		import forgery_py

		seed()
		for i in range(count):
			u = User(email = forgery_py.internet.email_address(),
					username = forgery_py.internet.user_name(True),
					password = forgery_py.lorem_ipsum.word(),
					confirmed = True,
					name = forgery_py.name.full_name(),
					location = forgery_py.address.city(),
					about_me = forgery_py.lorem_ipsum.sentence(),
					member_since = forgery_py.date.date(True))
			db.session.add(u)
			try:
				db.session.commit()
			except IntegrityError as e:
				db.session.rollback()

	def generate_auth_token(self, expiration):
		s = Serializer(current_app.config['SECRET_KEY'], 
						expires_in=expiration)
		return s.dumps({'id':self.id}).decode('ascii')

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return None
		return User.query.get(data['id'])

	def to_json(self):
		json_user = {
			'url': url_for('api.get_user', id=self.id, _external=True),
			'username': self.username,
			'member_since': self.member_since,
			'last_seen': self.last_seen,
			'posts': url_for('api.get_user_posts', id=self.id, _external=True),
			'followed_posts': url_for('api.get_user_followed_posts',
									id=self.id, _external=True),
			'post_count': self.posts.count()
		}
		return json_user

	def __repr__(self):
		return '<User %r>' % self.username

class Post(db.Model):
	__tablename__ = 'posts'
	id = db.Column(db.Integer, primary_key=True)
	body = db.Column(db.Text)
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	body_html = db.Column(db.Text)
	comments = db.relationship('Comment', backref='post', lazy='dynamic')

	@staticmethod
	def generate_fake(count=100):
		from random import seed, randint
		import forgery_py

		seed()
		user_count = User.query.count()
		for i in range(count):
			u = User.query.offset(randint(0, user_count-1)).first()
			p = Post(body = forgery_py.lorem_ipsum.sentences(randint(1, 3)),
					timestamp = forgery_py.date.date(True),
					author = u)
			db.session.add(p)
			db.session.commit()

	def to_json(self):
		json_post = {
			'url' : url_for('api.get_post', id=self.id, _external=True),
			'body': self.body,
			'body_html': self.body_html,
			'timestamp': self.timestamp,
			'author': url_for('api.get_user', id=self.author_id,
								_external=True),
			'comments': url_for('api.get_post_comments', id=self.author_id,
								_external=True),
			'comment_count': self.comments.count()
		}
		return json_post

	@staticmethod
	def from_json(json_post):
		body = json_post.get('body')
		if body is None or body=='':
			raise ValidationError('post dose not have a body')
		return Post(body=body)

	@staticmethod
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote',
						'code', 'em', 'i', 'li', 'ol', 'pre', 'strong',
						'ul', 'h1', 'h2', 'h3', 'p']
		target.body_html = bleach.linkify(bleach.clean(
			markdown(value, output_format='html'),
			tags=allowed_tags, strip=True))

db.event.listen(Post.body, 'set', Post.on_changed_body)

class Comment(db.Model):
	__tablename__ = 'comments'
	id = db.Column(db.Integer, primary_key=True)
	body = db.Column(db.Text)
	body_html = db.Column(db.Text)
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	disabled = db.Column(db.Boolean)
	author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

	def to_json(self):
		json_comment = {
			'url': url_for('api.get_comment', id=self.id,
							_external=True),
			'body': self.body,
			'body_html': self.body_html,
			'timestamp': self.timestamp,
			'disabled': self.disabled,
			'author': url_for('api.get_user', id=self.author_id,
								_external=True),
			'post': url_for('api.get_post', id=self.post_id,
								_external=True)
		}
		return json_comment

	@staticmethod
	def on_changed_body(target, value, oldvalue, initiator):
		allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em',
						'i', 'strong']
		target.body_html = bleach.linkify(bleach.clean(
			markdown(value, output_format='html'),
			tags=allowed_tags, strip=True))

db.event.listen(Comment.body, 'set', Comment.on_changed_body)



class AnonymousUser(AnonymousUserMixin):
	def can(self, permissions):
		return False

	def is_administrator(self):
		return False

login_manager.anonymous_user = AnonymousUser

class Permission:
	FOLLOW = 0x01
	COMMENT = 0x02
	WRITE_ARTICLES = 0x04
	MODERATE_COMMENTS = 0x08
	ADMINISTER = 0x80


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))








