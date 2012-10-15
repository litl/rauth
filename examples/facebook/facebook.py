'''
    facebook
    --------

    A simple Flask demo app that shows how to login with Facebook via rauth.

    Please note: you must do `from facebook import db; db.create_all()` from
    the interpreter before running this example!
    
    Due to Facebook's stringent domain validation, requests using this app 
    must originate from 127.0.0.1:5000.
'''

from flask import Flask, flash, request, redirect, render_template, url_for
from flask.ext.sqlalchemy import SQLAlchemy

from rauth.service import OAuth2Service

# rauth OAuth 2.0 service wrapper
graph_url = 'https://graph.facebook.com/'
facebook = OAuth2Service(name='facebook',
                         authorize_url='https://www.facebook.com/dialog/oauth',
                         access_token_url=graph_url + 'oauth/access_token',
                         consumer_key='440483442642551',
                         consumer_secret='cd54f1ace848fa2a7ac89a31ed9c1b61')

# Flask config
SQLALCHEMY_DATABASE_URI = 'sqlite:///facebook.db'
SECRET_KEY = '\xfb\x12\xdf\xa1@i\xd6>V\xc0\xbb\x8fp\x16#Z\x0b\x81\xeb\x16'
DEBUG = True

# Flask setup
app = Flask(__name__)
app.config.from_object(__name__)
db = SQLAlchemy(app)


# models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    fb_id = db.Column(db.String(120), unique=True)

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return '<User %r>' % self.username

    @staticmethod
    def get_or_create(username, fb_id):
        rv = User.query.filter_by(fb_id=fb_id).first()
        if rv is None:
            rv = User(username, fb_id)
            db.session.add(rv)
        return rv


# views
@app.route('/')
def index():
    return render_template('login.html')


@app.route('/facebook/login')
def login():
    redirect_url = url_for('authorized', _external=True)
    return redirect(facebook.get_authorize_url(redirect_uri=redirect_url))


@app.route('/facebook/authorized')
def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('index'))

    # make a request for the access token credentials using code
    redirect_uri = url_for('authorized', _external=True)
    data = dict(code=request.args['code'], redirect_uri=redirect_uri)
    auth = facebook.get_access_token(data=data).content

    # the "me" response
    me = facebook.get(graph_url + '/me',
                      params=dict(access_token=auth['access_token'])).content

    User.get_or_create(me['username'], me['id'])
    flash('Logged in as ' + me['name'])
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
