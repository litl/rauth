from rauth.service import OAuth2Service
import webbrowser
from pprint import pprint

# Get a real consumer key & secret from:
# https://github.com/settings/applications/new

NAME = 'github'
AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
CLIENT_ID = ''
CLIENT_SECRET = ''
API = 'https://api.github.com/user'
SCOPE = "repo user"

svc = OAuth2Service(name=NAME,
                    authorize_url=AUTHORIZE_URL,
                    access_token_url=ACCESS_TOKEN_URL,
                    consumer_key=CLIENT_ID,
                    consumer_secret=CLIENT_SECRET)

authorize_url = svc.get_authorize_url(scope=SCOPE)

print 'Visit this URL in your browser: ' + authorize_url
webbrowser.open(authorize_url)

code = raw_input('Enter code parameter (code=something) from URL: ')

# create a dictionary for the data we'll post on the get_access_token request
data = dict(code=code)

# retrieve the access token
resp = svc.get_access_token('POST', data=data).content
svc.access_token = resp['access_token']

# make a request using the access token
user = svc.get(API).content

pprint(user)
