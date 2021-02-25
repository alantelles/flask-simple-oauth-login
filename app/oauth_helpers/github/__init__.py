import os
import urllib.parse
import base64, hashlib
import re
import requests
import json
import datetime
import traceback
from flask import request, session, redirect

from app.oauth_helpers import OAuthHelper


class GitHubOAuthHelper(OAuthHelper):
    def __init__(self, oauth_login, oauth_token, redirect_uri, client_id, client_secret):
        super().__init__(oauth_login, oauth_token, None, redirect_uri, client_id, client_secret)

    def get_user_data(self):
        oauth_login, code_verifier = self._generate_login_ouath_uri()
        if 'state' in request.args:
            try:
                print('Returning from github')
                session['oauth_user']['state'] = request.args['state']
                session['oauth_user']['code'] = request.args['code']

                payload = {
                    'grant_type': 'authorization_code',
                    'redirect_uri': self.redirect_uri,
                    'code_verifier': session['oauth_user']['code_verifier'],
                    'code': session['oauth_user']['code'],
                    'client_id': self.client_id,
                    'state': session['oauth_user']['state'],
                    'client_secret': self.client_secret
                }
                print("Trying get user data")

                auth_try = requests.post(
                    self.oauth_token, 
                    data=payload,
                    headers={'Accept': 'application/json'},
                    allow_redirects=False
                )
                json_pay = auth_try.json()
                print('body: ', json_pay)
                if 'error' not in json_pay:
                    access_token = json_pay['access_token']
                    bearer = f'token {access_token}'
                    try:
                        user = requests.get(
                            'https://api.github.com/user',
                            headers= {
                                "Accept": "application/vnd.github.v3+json",
                                "Authorization": bearer
                            }
                        )
                        with open('ret.json', 'wt') as ret:
                            ret.writelines(user.text)
                        user = user.json()
                        
                        session['oauth_user']['username'] = user['login']
                        session['oauth_user']['user_logged'] = True
                        session.permanent = True
                        print('user logged, returning info: ', user)
                        return None, user
                        
                    except KeyError as e:
                        traceback.print_exc()
                        del session['oauth_user']
                        print(f'Key {e} not present. Unauthorized credentials')
                        session.permanent = True
                        return redirect(oauth_login), None

                else:
                    print('Invalid login request')
                    session['oauth_user'] = {}
                    session['oauth_user']['code_verifier'] = code_verifier
                    session['oauth_user']['user_logged'] = False
                    
                    session.permanent = True
                    return redirect(oauth_login), None

            except:
                traceback.print_exc()
                print('Invalid access request')
                session['oauth_user'] = {}
                session['oauth_user']['code_verifier'] = code_verifier
                session['oauth_user']['user_logged'] = False
                print('Trying login in backstage')
                session.permanent = True
                return redirect(oauth_login), None

        else:
            if not session['oauth_user']['user_logged']:
                session['oauth_user'] = {}
                session['oauth_user']['code_verifier'] = code_verifier
                session['oauth_user']['user_logged'] = False
                print('Trying login in backstage')
                session.permanent = True
                return redirect(oauth_login), None



    def authenticate(self):
        
        oauth_login, code_verifier = self._generate_login_ouath_uri()
        
        if not 'oauth_user' in session:
            session['oauth_user'] = {}
            session['oauth_user']['code_verifier'] = code_verifier
            session['oauth_user']['user_logged'] = False
            
            return redirect(oauth_login)

        