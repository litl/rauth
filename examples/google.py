from rauth.service import OAuth2Service

# Get a real consumer key & secret from:
# https://code.google.com/apis/console/
google = OAuth2Service(
    name='google',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    consumer_key='',
    consumer_secret='')

redirect_uri = 'https://github.com/litl/rauth/'

print 'Visit this URL in your browser: ' + google.get_authorize_url(redirect_uri=redirect_uri, scope='profile email')

# This is a bit cumbersome, but you need to copy the code=something (just the
# `something` part) out of the URL that's redirected to AFTER you login and
# authorize the demo application
code = raw_input('Enter code parameter (code=something) from URL: ')

# create a dictionary for the data we'll post on the get_access_token request
data = dict(code=code, grant_type='authorization_code', redirect_uri=redirect_uri)

# retrieve the access token
access_token = \
    google.get_access_token('POST', data=data).content['access_token']

# make a request using the access token
user = google.get('https://www.googleapis.com/oauth2/v1/userinfo',
                  params=dict(access_token=access_token)).content

print 'currently logged in as: ' + user['email']
