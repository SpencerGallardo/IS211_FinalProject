#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Final Project"""

# Python module
import os
import re
import datetime

# Third party packages
from flask import Flask, Markup, render_template,  request, \
    redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from flask_login import LoginManager, login_user, logout_user, current_user

# Create Flask app instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


csrf = CSRFProtect(app)

# SQLAlchemy database instance
db = SQLAlchemy(app)

# Flask-Login Initialization
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(userid):
    return User.query.filter(User.id==userid).first()


# Database model declaration
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))

    posts = db.relationship('Post', backref='user', lazy=True)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    slug = db.Column(db.String(50), unique=True)
    content = db.Column(db.Text)
    published = db.Column(db.Boolean, unique=False, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)


# Flask-WTF class based form for validating input
class SignupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class SigninForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


@app.before_first_request
def before_first_request_init_db():
    """
    Make sure database initialization done when make the first request
    """
    db.create_all()


@app.route('/')
def index():
    """
    Main url function that returns all the post
    """
    posts = Post.query.order_by('-timestamp').all()
    return render_template('pages/index.html', posts=posts)


@app.route('/user/posts/<user_id>')
def user_posts(user_id):
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('pages/index.html', posts=posts)


@app.route('/signup', methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('User already exists, Please signin using old password', 'warning')
            return redirect(url_for('signin'))

        user = User(email=form.email.data)
        user.name = form.name.data
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        # Update the user and redirect
        flash("User created successfully", 'primary')
        return redirect(url_for('index'))

    return render_template('pages/signup.html', form=form)


@app.route('/signin', methods=["GET", "POST"])
def signin():
    form = SigninForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # Return to signin page if user not here
        if not user:
            flash('Please enter correct email/password', 'danger')
            return redirect(url_for('signin'))
        if user.check_password(form.password.data):
            login_user(user)
            flash('Login success', 'primary')
            return redirect(url_for('index'))
        else:
            return redirect(url_for('signin'))
    else:
        print(form.errors)
    return render_template('pages/signin.html', form=form)


@app.route('/signout')
def signout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/post/<slug>')
def post_slug(slug):
    post = Post.query.filter_by(slug=slug).first()
    return render_template('pages/post.html', post=post)


@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        # Create Blog object
        post = Post()
        post.title = title
        post.slug = re.sub('[^\w]+', '-', title.lower())
        post.content = content
        post.user_id = current_user.id
        
        # Adding into db and commit
        db.session.add(post)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('pages/add.html')


@app.route('/edit/<slug>', methods=['GET', 'POST'])
def edit(slug):
    post = Post.query.filter_by(slug=slug).first()

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        post.title = title
        post.slug = re.sub('[^\w]+', '-', title.lower())
        post.content = content
        
        # Adding into db and commit
        db.session.add(post)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('pages/edit.html', post=post)


@app.route('/delete/<slug>')
def delete(slug):
    post = Post.query.filter_by(slug=slug).first()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('user_posts', user_id=current_user.id))


if __name__ == '__main__':
    app.run()
