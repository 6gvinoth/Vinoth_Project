# app.py
from Vinoth_Project import app
from flask import render_template
from flask_login import login_required, current_user


@app.route('/')
def index():
    return render_template("index.html")


