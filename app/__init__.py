import os
from flask import Flask
from app.blueprints.github import github_views

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret')

app.register_blueprint(github_views, url_prefix='/github')

from app import routes