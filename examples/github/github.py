from flask import Flask, flash, request, redirect, render_template, url_for, session
from flask.ext.sqlalchemy import SQLAlchemy

from rauth.service import OAuth2Service

# Flask config
SQLALCHEMY_DATABASE_URI = 'sqlite:///github.db'
SECRET_KEY = '\xfb\x12\xdf\xa1@i\xd6>V\xc0\xbb\x8fp\x16#Z\x0b\x81\xeb\x16'
DEBUG = True

# Flask setup
app = Flask(__name__)
app.config.from_object(__name__)
db = SQLAlchemy(app)

github = OAuth2Service(
    name='github',
    base_url='https://api.github.com/',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    client_id= '477151a6a9a9a25853de',
    client_secret= '23b97cc6de3bea712fddbef70a5f5780517449e4',
)

# models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True)
    name = db.Column(db.String(120))

    def __init__(self, login, name):
        self.login = login
        self.name = name

    def __repr__(self):
        return '<User %r>' % self.login

    @staticmethod
    def get_or_create(login, name):
        user = User.query.filter_by(login=login).first()
        if user is None:
            user = User(login, name)
            db.session.add(user)
            db.session.commit()
        return user

# views
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/about')
def about():
    if session.has_key('token'):
        auth = github.get_session(token = session['token'])
        resp = auth.get('/user')
        if resp.status_code == 200:
            user = resp.json()

        return render_template('about.html', user = user)
    else:
        return redirect(url_for('login'))


@app.route('/login')
def login():
    redirect_uri = url_for('authorized', next=request.args.get('next') or request.referrer or None, _external=True)
    print(redirect_uri)
    params = {'redirect_uri': redirect_uri, 'scope': 'user:email'}
    print(github.get_authorize_url(**params))
    return redirect(github.get_authorize_url(**params))

@app.route('/github/callback')
def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('index'))

    # make a request for the access token credentials using code
    redirect_uri = url_for('authorized', _external=True)

    data = dict(code=request.args['code'],
        redirect_uri=redirect_uri,
        scope='user:email,public_repo')

    auth = github.get_auth_session(data=data)

    # the "me" response
    me = auth.get('user').json()

    user = User.get_or_create(me['login'], me['name'])


    session['token'] = auth.access_token
    session['user_id'] = user.id

    flash('Logged in as ' + me['name'])
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()
    app.run()
