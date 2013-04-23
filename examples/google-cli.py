from rauth.service import OAuth2Service

import webbrowser

from secrets import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI

# Get a real consumer key & secret from:
# https://code.google.com/apis/console/
google = OAuth2Service(
    name='google',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET)

redirect_uri = GOOGLE_REDIRECT_URI

params = {
    'scope': 'profile email',
    'response_type': 'token',
    'redirect_uri': redirect_uri
}

authorize_url = google.get_authorize_url(**params)

print 'Visit this URL in your browser: ' + authorize_url
webbrowser.open(authorize_url)

# If we have already done this, google will reply with an access_token directly
what = raw_input("Did you receive a code or an access token [code/access] ? ")
if what == 'code' :
    # This is a bit cumbersome, but you need to copy the code=something (just the
    # `something` part) out of the URL that's redirected to AFTER you login and
    # authorize the demo application
    code = raw_input('Enter code parameter (code=something) from URL: ')

    # create a dictionary for the data we'll post on the get_access_token request
    data = dict(code=code, grant_type='authorization_code', redirect_uri=redirect_uri)

    # retrieve the access token
    access_token = \
                 google.get_access_token('POST', data=data).content['access_token']
else:
    access_token = raw_input('Enter the access_token from URL: ')

session = google.get_session(access_token)

# make a request using the session
user = session.get('https://www.googleapis.com/oauth2/v1/userinfo').json()

print 'currently logged in as: ' + user['email']
