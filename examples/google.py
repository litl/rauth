from rauth.service import OAuth2Service
import webbrowser

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
    consumer_secret='')

redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
authorize_url = google.get_authorize_url(redirect_uri=redirect_uri,
                                         scope='profile email')

print 'Visit this URL in your browser: ' + authorize_url
webbrowser.open(authorize_url);

code = raw_input('Copy code from browser: ')

# create a dictionary for the data we'll post on the get_access_token request
data = dict(code=code,
            grant_type='authorization_code',
            redirect_uri=redirect_uri)

# retrieve the access token
resp = google.get_access_token('POST', data=data)
access_token = resp.content['access_token']

# make a request using the access token
user = google.get('https://www.googleapis.com/oauth2/v1/userinfo',
                  access_token=access_token).content

print 'currently logged in as: ' + user['email']
