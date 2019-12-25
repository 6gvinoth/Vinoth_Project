# app.py
from Vinoth_Project import app

from flask import Flask
from flask import url_for, render_template, request ,flash
from flask import redirect, jsonify
from flask_mongoengine import MongoEngine
from flask_mongoengine.wtf import model_form
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os

app.config['MONGODB_SETTINGS'] = {
	'db': 'Vinoth_Project',
}

db = MongoEngine(app)
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

@login_manager.user_loader
def load_user(user_id):
	try:
		user = User.objects.get(username=user_id)
	except:
		user=None
	return user

#User Model
class User(db.Document):
	

	username = db.StringField(max_length=50, required=True, unique=True)
	email = db.StringField(max_length=100, required=True)
	password = db.StringField(max_length=100, required=True)
	has_usable_password = db.BooleanField(default=True)

	def __repr__(self):
		return '<User %r>' % self.username
	def is_authenticated(self):
		return True
	def is_active(self):
		return True
	def is_anonymous(self):
		return False
	def get_id(self):
		return str(self.username)




@app.route('/', methods=['GET', 'POST'])
def index():
	if request.method=='GET': #Send the login form
		return render_template('index.html')
	elif request.method=='POST': #Login the user
		#Get the post data
                
		username = request.form.get('username')
		password = request.form.get('password')
		#Query for user from database and check password
		try:
			user = User.objects.get_or_404(username=username)
		except:
			user = None

		if user == None:
			flash("Invalid Username or Password", "danger") 
			return redirect(request.url)
		else:
			if user.has_usable_password:
				if bcrypt.check_password_hash(user.password, password) :
					login_user(user)
					return "Login Successful"
				else:
					flash("Password is incorrect","danger")
					return redirect(request.url)
			else: #No usable password
				flash("User has no Password","danger")
				return redirect(request.url)

@app.route('/signup/', methods=['GET', 'POST'])
def signup():
	if request.method=='GET': #Send the signup form
		return render_template('signup.html')
	elif request.method=='POST': #Signup the user
		#Get the post data
		username = request.form.get('username')
		email    = request.form.get('email')
		password = request.form.get('password')
		confirm_password = request.form.get('confirmpassword')

		
		#Create New User and Save to Database
		pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
		newuser = User(username=username, email=email, password=pw_hash)
		newuser.save()

		#Return Success Message
		return "Signup Successful"
		
		
