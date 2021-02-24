import os
from flask import redirect, render_template_string, render_template, url_for, session
from app import app

from app.oauth_helpers.github import GitHubOAuthHelper

def verify_login(fn):
    def wrapper(*args):
        if 'oauth_user' in session:
            if session['oauth_user']['user_logged']:
                return fn(*args)

        else:
            return redirect(url_for('login'))

    return wrapper


@app.route("/")
@verify_login
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    try:
        del session['oauth_user']
    except:
        pass
    return render_template("logout.html")

@app.route('/logged')
def logged():
    return 'logged'

@app.route("/login")
def login():
    return render_template('login.html')


