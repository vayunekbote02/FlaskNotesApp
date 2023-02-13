from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, Note
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged In successfully!", category="success")
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect password, try again.", category="error")
        else:
            flash("User does not exist", category="error")
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash("Note is too short", category="error")
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash("Note added", category="success")
    return render_template("home.html", user=current_user)


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash("This email is already in use.", category="error")
        if len(email) < 4:
            flash("Email must be greater than 3 characters.", category="error")
        elif len(firstname) < 1:
            flash("Please enter a valid firstname.", category="error")
        elif len(password1) < 8:
            flash(
                "Please enter a password greater than 7 characters for your safety.", category="error")
        elif password1 != password2:
            flash("Passwords do not match!", category="error")
        else:
            new_user = User(email=email, firstname=firstname, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()

            flash("Account created successfully!", category="success")

            login_user(new_user, remember=True)
            return redirect(url_for('auth.home'))
    return render_template("signup.html", user=current_user)
