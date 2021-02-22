import os

from flask import Blueprint, url_for, session, render_template, redirect
from app.oauth_helpers.github import GitHubOAuthHelper


github_views = Blueprint('github_views', __name__, template_folder='templates')

@github_views.route('auth')
def auth():
    oauth = GitHubOAuthHelper(
        'https://github.com/login/oauth/authorize',
        'https://github.com/login/oauth/access_token',
        'http://localhost:5000/github/user',
        'c911d0a0203a46c77427',
        os.environ.get('CLIENT_SECRET')
    )
    auth_try = oauth.authenticate()
    if auth_try:
        return auth_try

    else:
        return render_template('github/user_index.html')

@github_views.route('user')
def get_user_data():
    oauth = GitHubOAuthHelper(
        'https://github.com/login/oauth/authorize',
        'https://github.com/login/oauth/access_token',
        'http://localhost:5000/github/user',
        'c911d0a0203a46c77427',
        os.environ.get('CLIENT_SECRET')
    )
    shall_redirect, user_info = oauth.get_user_data()
    if shall_redirect:
        return shall_redirect

    session['oauth_user']['user_info'] = user_info

    return redirect(url_for('github_views.show_user'))

@github_views.route('show_user')
def show_user():
    user_info = session['oauth_user']['user_info']
    return render_template('github/user_index.html', user_info=user_info)