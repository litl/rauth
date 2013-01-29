from rauth.service import OAuth2Service
import webbrowser
from pprint import pprint

# Get a real consumer key & secret from:
# https://code.google.com/apis/console/
#
# When creating a client id choose:
#   - Application type: Installed application
#   - Installed application type: Other
#
# For existing client id's, from "Edit settings":
#   - Platform: Other

NAME = 'google'
AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/auth'
ACCESS_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
CLIENT_ID = ''
CLIENT_SECRET = ''
API = 'https://www.googleapis.com/oauth2/v1/userinfo'


svc = OAuth2Service(name=NAME,
                    authorize_url=AUTHORIZE_URL,
                    access_token_url=ACCESS_TOKEN_URL,
                    consumer_key=CLIENT_ID,
                    consumer_secret=CLIENT_SECRET)


authorize_url = svc.get_authorize_url(redirect_uri=REDIRECT_URI,
                                      scope='profile email')

print 'Visit this URL in your browser: ' + authorize_url
webbrowser.open(authorize_url)

code = raw_input('Copy code from browser: ')

# create a dictionary for the data we'll post on the get_access_token request
data = dict(code=code,
            grant_type='authorization_code',
            redirect_uri=REDIRECT_URI)

# retrieve the access token
resp = svc.get_access_token('POST', data=data).content
svc.access_token = resp['access_token']

# make a request using the access token
user = svc.get(API).content

pprint(user)
