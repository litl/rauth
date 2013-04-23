'''
    google
    ------

    A simple Flask demo app that shows how to login with Google via rauth.

    Please note: you must do `from google import db; db.create_all()` from
    the interpreter before running this example!

    Due to Google's stringent domain validation, requests using this app
    must originate from 127.0.0.1:5000.

    You must configure the redirect_uri in the Google API console. In this case,
    it is: http://127.0.0.1:5000/google/authorized
'''

from flask import Flask, flash, request, redirect, render_template, url_for
from flask.ext.sqlalchemy import SQLAlchemy

from rauth.service import OAuth2Service

import time

# Flask config
SQLALCHEMY_DATABASE_URI = 'sqlite:///google.db'
SECRET_KEY = '\xfb\x12\xdf\xa1@i\xd6>V\xc0\xbb\x8fp\x16#Z\x0b\x81\xeb\x16'
DEBUG = True

from secrets import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GOOGLE_TEST_EMAIL

# Flask setup
app = Flask(__name__)
app.config.from_object(__name__)
db = SQLAlchemy(app)

# rauth OAuth 2.0 service wrapper
google = OAuth2Service(name='google',
                       authorize_url='https://accounts.google.com/o/oauth2/auth',
                       access_token_url='https://accounts.google.com/o/oauth2/token',
                       client_id=app.config['GOOGLE_CLIENT_ID'],
                       client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                       base_url=None)

# models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    google_id = db.Column(db.String(120))
    access_token = db.Column(db.String(500))
    expires_at = db.Column(db.Integer)

    def __init__(self, username, google_id, access_token, expires_at):
        self.username = username
        self.google_id = google_id
        self.access_token = access_token
        self.expires_at = expires_at

    def __repr__(self):
        return '<User %r>' % self.username

    @staticmethod
    def get(username):
        user = User.query.filter_by(username=username).first()
        return user

    @staticmethod
    def get_or_create(username, google_id, access_token, expires_at):
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(username, google_id, access_token, expires_at)
            db.session.add(user)
            db.session.commit()
        return user


# views
@app.route('/')
def index():
    return render_template('login.html')


@app.route('/google/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    params = {
        'scope': 'email',
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'access_type' : 'offline',
    }
    return redirect(google.get_authorize_url(**params))

@app.route('/google/reuse')
def reuse():
    user = User.get(GOOGLE_TEST_EMAIL)
    current = int(time.time())
    if not user or user.expires_at < current :
        redirect(url_for('login'))
    # setup the session using the access_token
    session = google.get_session(user.access_token)
    # the user object as returned by google
    user = session.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    flash('Reused logging session as ' + user['email'])
    return redirect(url_for('index'))

@app.route('/google/authorized')
def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('index'))

    # make a request for the access token credentials using code
    redirect_uri = url_for('authorized', _external=True)
    data = {
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
    }
    response = google.get_raw_access_token(data=data)
    response = response.json()
    access_token = response['access_token']
    expires_in = response['expires_in']
    expires_at = int(time.time()) + response['expires_in']

    # setup the session using the access_token
    session = google.get_session(access_token)

    # the user object as returned by google
    user = session.get('https://www.googleapis.com/oauth2/v1/userinfo').json()

    # create the user, save the access_token, and the expire_at, so that
    # we can later verify if the access token is still valid
    User.get_or_create(user['email'], user['id'], response['access_token'], expires_at)

    flash('Logged in as ' + user['email'])
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.run()
