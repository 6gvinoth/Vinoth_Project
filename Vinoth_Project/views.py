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
import random
import smtplib
from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
from flask_dance.contrib.google import make_google_blueprint, google
from raven.contrib.flask import Sentry

import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config['MONGODB_SETTINGS'] = {
	'db': 'login',
}

db = MongoEngine(app)
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

oauth = OAuth(app)

github = oauth.remote_app(
    'github',
    consumer_key='647f43348b00653614a3',
    consumer_secret='1c65993544cb3a17739e7be3268b1a8decf22053',
    request_token_params={'scope': 'user:email'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)
sentry = Sentry(app)	

app.config["GOOGLE_OAUTH_CLIENT_ID"] = "685055809680-748eugrpphh5ccijpj7lccck6roeu0sh.apps.googleusercontent.com"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "kZXIzzfJP6f4XVLcfOxfmGkn"


google_bp = make_google_blueprint(
    client_id=app.config.get('GOOGLE_LOGIN_CLIENT_ID'),
    client_secret=app.config.get('GOOGLE_LOGIN_CLIENT_SECRET'),
    scope=["openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",]
)
app.register_blueprint(google_bp, url_prefix="/glogin")

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


@app.route('/')
@login_required
def home():
	return 'welcome'

@app.route('/login', methods=['GET', 'POST'])
def index():
	if request.method=='GET': #Send the login form
		return render_template('index.html')
	elif request.method=='POST': #Login the user
		#Get the post data
                
		username = request.form.get('username')
		password = request.form.get('password')
		if username =='' or password == '' :
			flash('Please Enter Username & Password ','danger')
			return redirect(request.url)
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
		#import pdb;pdb.set_trace() 
		username = request.form.get('username')
		email    = request.form.get('email')
		password = request.form.get('password')
		confirm_password = request.form.get('confirmpassword')
		if username =='' or  email =='' or password == '' or confirm_password =='':
			flash('Please Fill All Recuried Fields','danger')
			return redirect(request.url)
		if password!=confirm_password:
			flash('Password MissMatch','danger')
			return redirect(request.url)
		try:
			user = User.objects.get_or_404(username=username)
		except:
			user=None
		if user != None:
			flash("user allready Exits use Different Name", "danger") 
			return redirect(request.url)

		#Create New User and Save to Database
		pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
		newuser = User(username=username, email=email, password=pw_hash)
		newuser.save()
		flash("Successfully Sigined","success")
		#Return Success Message
		return redirect('/')

@app.route("/logout/")
@login_required
def logout():
	logout_user()
	return "Logged out Successfully"
		
		
@app.route("/forgot_password/", methods=['GET', 'POST'])
def forgot_password():
	if request.method=='GET': #Send the forgot password form
		return render_template('forgot_password.html')

	elif request.method=='POST': 
		#Get the post data
		username = request.form.get('username')
		if username is None or username=='':
			flash('Please Enter Username ','danger')
			return redirect(request.url)
		try:
			user = User.objects.get_or_404(username=username)
		except:
			user = None
		if user is None :
			flash('Invalid Username ','danger')
			return redirect(request.url)
		#Generate Random Pass and Set it to User object
		
		s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		passlen = 16
		generated_password =  "".join(random.sample(s,passlen ))
		
		pw_hash = bcrypt.generate_password_hash(generated_password).decode('utf-8')
		user.password = pw_hash
		user.save()
		s = smtplib.SMTP('smtp.gmail.com', 587) 
		s.starttls() 
		s.login("vinothvgvg@gmail.com", "78458554577")
		message='''Your new password is "%s"'''%generated_password
		
		s.sendmail("vinothvgvg@gmail.com", user.email, message)
		s.quit()
		flash("Successfully Mail Sended ","success")
		#Return Success Message
		return redirect('/')

@app.route('/github_login/')
def login():
    return github.authorize(callback=url_for('authorized', _external=True))
@app.route('/github_login/authorized')
def authorized():
    
    resp = github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp
        )
    session['github_token'] = (resp['access_token'], '')
    me = github.get('user')
    username = me.data['login']
    try:
    	user = User.objects.get(username=username)
    except:
    	password = "UNUSABLE_PASSWORD"
    	user = User(username=username, email=username, password=password)
    	user.has_usable_password = False
    	user.save()
    login_user(user)
    return "Logged in as {0}".format(username)


@app.route("/glogin/")
def glogin():
	#Let flask-dance do its magic
	if not google.authorized:
		
		return redirect(url_for("google.login"))
	resp = google.get("/plus/v1/people/me")
	assert resp.ok, resp.text    
	#Get/Create user
	username = resp.json()['emails'][0]['value']
	try:
		user = User.objects.get(username=username)
	except:
		password = "UNUSABLE_PASSWORD"
		user = User(username=username, email=username, password=password)
		user.has_usable_password = False
		user.save()
	#Login the user
	login_user(user)
	return "Logged in as {0}".format(username)

@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')
