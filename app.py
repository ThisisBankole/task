import os
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask.cli import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


# Define the user class which will represent users of your application. 
# They contain data about the user and methods that describe what users can do or what can be done to them.
class User(UserMixin):
    def __init__ (self, dictionary):
        self.id = dictionary['id']
        self.email = dictionary['email']
        self.password = dictionary['password']

app = Flask(__name__)
bcrypt = Bcrypt(app)


load_dotenv()
print(load_dotenv())

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

#login handlers
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    user = db.execute("SELECT * FROM users WHERE id = :id", id=user_id)
    if len(user) != 1:
        return None
    return User(user[0])

# Connect to database
db = SQL("sqlite:///database.db")

# enable foreign keys
db.execute("PRAGMA foreign_keys = ON")
app.config["SECRET_KEY"] = os.getenv('SECRET_KEY')


# Signup Form
class RegisterForm(FlaskForm):
    
    
    name = StringField(label="Full Name", validators=[InputRequired(), Length(min=2, max=100)], render_kw={"placeholder" : "Name"})
    
    email = StringField(label= "Email Address", validators=[InputRequired(), Length(min=2, max=200)],render_kw={"placeholder" : "Email Address"} )
    
    password = PasswordField(label="Password", validators=[InputRequired(), Length(min=8, max=50)], render_kw={"placeholder" : "Password"})
    
    submit = SubmitField("Register")
    
    #Validate Email Address of user 
    
    def validate_email(self, email):
        existing_email = db.execute("SELECT * FROM users WHERE email= :email", email=email.data)
        
        if existing_email:
            raise ValidationError(
                "This email already exist"
            )

# Login Form
class LoginForm(FlaskForm):
    
    email = StringField(label= "Email Address", validators=[InputRequired(), Length(min=2, max=200)],render_kw={"placeholder" : "Email Address"} )
    
    password = PasswordField(label="Password", validators=[InputRequired(), Length(min=8, max=50)], render_kw={"placeholder" : "Password"})
    
    submit = SubmitField("Log In")
    
# Task Forrm
class TaskForm(FlaskForm):
    task = StringField(label= "Task Name" , validators=[InputRequired()], render_kw={"placeholder" : "Add Task Name"})
    date = DateField('DatePicker', validators=[InputRequired()], format='%Y-%m-%d')
    submit = SubmitField("Add Task")


@app.route("/")
def home():
    return render_template("home.html")


#Login Route
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        # Query the database for the user
        user = db.execute("SELECT * FROM users WHERE email = :email", email=email)
         # The hash matches the password in the database, log the user in
        if user and bcrypt.check_password_hash(user[0]['password'], password):
            #save user email in the session
            new_user = User(user[0])
            login_user(new_user)
            #redirect to dashboard
            return redirect(url_for('dashboard'))
        
    return render_template("login.html", form=form)


#log out route
@app.route("/logout")
def logout():
    session.clear()  # Clear the session
    return redirect(url_for('login'))


#Register route
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        #initialise register form data
        name = form.name.data
        email = form.email.data
        password = form.password.data
        
        #encrypt password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
         # Insert the new user data into the database
        new_user = db.execute("INSERT INTO users (name, email, password) VALUES (:name, :email, :password)", name=name, email=email, password=hashed_password)
        
        # redirect
        return redirect(url_for('dashboard'))
    
    return render_template("register.html", form=form)


#Dashboard route
@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    form = TaskForm()
    if request.method == "POST":
        task = form.task.data
        date = form.date.data
        #adding task into the db
        result = db.execute("INSERT INTO tasks (user_id, task, date) VALUES (:user_id, :task, :date)", user_id=current_user.id, task=task, date=date)
        if result:
            flash('your task was successfully added', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Something went wrong', 'danger')
            
    else:
        tasks = db.execute("SELECT date, task FROM tasks WHERE user_id = :user_id", user_id=current_user.id)
        return render_template("dashboard.html", form=form, tasks=tasks)
    
        return render_template("dashboard.html")