import webbrowser

from rauth.service import OAuth2Service

# Get a real consumer key & secret from:
# https://code.google.com/apis/console/
#
# When creating a client id choose:
#   - Application type: Installed application
#   - Installed application type: Other
#
# For existing client id's, from "Edit settings":
#   - Platform: Other

google = OAuth2Service(
    name='google',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    consumer_key='',
    consumer_secret='',
    base_url='https://www.googleapis.com/oauth2/v1/')

redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
params = {'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
          'scope': 'profile email'}

authorize_url = google.get_authorize_url(**params)

print 'Visit this URL in your browser: ' + authorize_url
webbrowser.open(authorize_url);

code = raw_input('Copy code from browser: ')

# create a dictionary for the data we'll post on the get_access_token request
data = {'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri}

# retrieve the access token
access_token = google.get_access_token('POST', data=data)['access_token']

# make a request using the access token
user = google.get('userinfo', access_token=access_token).json()

print 'currently logged in as: ' + user['email']
