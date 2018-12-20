#!/usr/bin/env python

from flask import Flask, redirect, request, session, url_for
from functools import wraps
from requests_oauthlib import OAuth1Session
import json
import os


# Application tokens (returned when the user registers an app)
API_HOST = '192.168.1.187'
API_KEY = 'a740ffb0-ba0a-4fab-a263-9bd909c311b7'
API_SECRET = 'CtI1VTfr6nTQqjPCwsmKUy9IRvCYxGZ8yvArdOUA'

# OAuth endpoints
API = 'http://%s/api' % API_HOST
REQUEST_TOKEN = '%s/oauth/request_token' % API
ACCESS_TOKEN = '%s/oauth/access_token' % API
AUTH_URL = 'http://%s/ui/#/authorize' % API_HOST

app = Flask(__name__)
_oauth_session = None


def protected(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        oauth = None
        if 'access_token' in session:
            token = session['access_token']
            oauth = OAuth1Session(API_KEY, API_SECRET, token['oauth_token'], token['oauth_token_secret'])
        kwargs['oauth'] = oauth
        return f(*args, **kwargs)
    return decorated


@app.route("/")
@protected
def index(oauth=None):
    if not oauth:
        return redirect(url_for('authorize'))

    # Access a protected resource using the access token
    headers = {'Accept': 'application/vnd.abiquo.user+json'}
    usr = oauth.get(API + "/login", headers=headers).json()
    return "<pre>%s</pre>" % json.dumps(usr, indent=4)


@app.route("/authorize")
def authorize():
    # Request an OAuth token and the authorization url
    global _oauth_session
    _oauth_session = OAuth1Session(API_KEY, API_SECRET, callback_uri=url_for('callback', _external=True))
    keys = _oauth_session.fetch_request_token(REQUEST_TOKEN)
    auth_url = '%s?oauth_token=%s' % (AUTH_URL, keys.get('oauth_token'))
    # Redirect to the provider to authorize the token. As it is an unauthenticated request,
    # the provider will ask for the credentials and redirect back to the configured callback
    # once the application has been authorized
    return redirect(auth_url)


@app.route("/callback")
def callback():
    # Parse the authorization response to extract the oauth_verifier
    res = _oauth_session.parse_authorization_response(request.url)
    # Request the access token that can be used to access the protected resources
    session['access_token'] = _oauth_session.fetch_access_token(ACCESS_TOKEN)
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    app.run(debug=True)
