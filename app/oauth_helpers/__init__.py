import os
import urllib.parse
import base64, hashlib
import re
import requests
import json
import datetime
import traceback
from flask import request, session, redirect


class OAuthHelper:
    def __init__(self, oauth_login, oauth_token, oauth_logout, redirect_uri, client_id, client_secret):
        self.oauth_login = oauth_login
        self.oauth_token = oauth_token
        self.oauth_logout = oauth_logout
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret

    
    def _b64_decode(data):
        data += '=' * (4 - len(data) % 4)
        return base64.b64decode(data).decode('utf-8')

    def _jwt_payload_decode(jwt):
        _, payload, _ = jwt.split('.')
        return json.loads(OAuthHelper._b64_decode(payload))

    def _generate_login_ouath_uri(self):
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')

        # redirect_uri_encoded = urllib.parse.quote_plus(redirect_uri)
        state = str(datetime.datetime.now()).encode()
        state = hashlib.sha256(state).hexdigest()

        query_dict = {
            
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'state': state,
            'client_id': self.client_id,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        query_string = '&'.join([key + '=' + urllib.parse.quote_plus(query_dict[key]) for key in query_dict])
        oauth_login = self.oauth_login + '?' + query_string
        return oauth_login, code_verifier

    def backstage_logout(prod_env):
        ISSUER = os.environ.get('OAUTH_ISSUER', '')
        ACC_URL = f'{BASE_URL}/auth/realms/globoi/protocol/openid-connect/logout'
        #if prod_env:
        #    ACC_URL = 'https://id.globo.com/auth/realms/globoi/protocol/openid-connect/logout'
        #    ACC_URL = 'https://globoid-connect.be.globoi.com/auth/realms/globoi/protocol/openid-connect/logout'
        
        # else:
        #   ACC_URL = 'https://id.qa.globoi.com/auth/realms/globoi/protocol/openid-connect/logout'
        #   ACC_URL = 'https://globoid-connect.be.qa.globoi.com/auth/realms/globoi/protocol/openid-connect/logout'

        token_hint = session['id_token']
        logout_user = f'{ACC_URL}?id_token_hint={token_hint}'
        del session['backstage_auth']
        log = requests.get(logout_user)
        session.permanent = False

    def authenticate(self):
        
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')

        # redirect_uri_encoded = urllib.parse.quote_plus(redirect_uri)
        state = str(datetime.datetime.now()).encode()
        state = hashlib.sha256(state).hexdigest()

        query_dict = {
            'scope': 'user',
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'state': state,
            'client_id': self.client_id,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        query_string = '&'.join([key + '=' + urllib.parse.quote_plus(query_dict[key]) for key in query_dict])
        oauth_login = self.oauth_login + '?' + query_string
        
        if not 'oauth_user' in session:
            session['oauth_user'] = {}
            session['oauth_user']['code_verifier'] = code_verifier
            session['oauth_user']['user_logged'] = False
            
            return redirect(oauth_login)

        elif 'state' in request.args:
            try:
                print('Returning from backstage')
                session['oauth_user']['state'] = request.args['state']
                # session['oauth_user']['session_state'] = request.args['session_state']
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
                print(session)
                print("Trying get user data")

                auth_try = requests.post(
                    self.oauth_token, 
                    data=payload,
                    headers={'Accept': 'application/json'},
                    allow_redirects=False
                )
                json_pay = auth_try.json()
                print(json_pay)
                if 'error' not in json_pay:
                    try:
                        decoded_jwt = OAuthHelper._jwt_payload_decode(json_pay['access_token'])
                        print(decoded_jwt)
                        sub = decoded_jwt['sub']
                        email = sub[sub.rfind(':')+1:]
                        username = email[:email.find('@')]
                        session['oauth_user']['email'] = email
                        session['oauth_user']['username'] = username
                        session['oauth_user']['user_logged'] = True
                        session['oauth_user']['id_token'] = json_pay['id_token']
                        session.permanent = True
                        
                    except:
                        del session['oauth_user']
                        print('Access token not present. Unauthorized credentials')
                        session.permanent = True
                        return redirect(oauth_login)

                else:
                    print('Invalid login request')
                    session['oauth_user'] = {}
                    session['oauth_user']['code_verifier'] = code_verifier
                    session['oauth_user']['user_logged'] = False
                    
                    session.permanent = True
                    return redirect(oauth_login)

            except:
                traceback.print_exc()
                print('Invalid access request')
                session['oauth_user'] = {}
                session['oauth_user']['code_verifier'] = code_verifier
                session['oauth_user']['user_logged'] = False
                print('Trying login in backstage')
                session.permanent = True
                return redirect(oauth_login)

        else:
            if not session['oauth_user']['user_logged']:
                session['oauth_user'] = {}
                session['oauth_user']['code_verifier'] = code_verifier
                session['oauth_user']['user_logged'] = False
                print('Trying login in backstage')
                session.permanent = True
                return redirect(oauth_login)