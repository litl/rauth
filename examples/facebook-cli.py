from rauth.service import OAuth2Service

import re
import webbrowser

# Get a real consumer key & secret from:
# https://developers.facebook.com/apps

facebook = OAuth2Service(
    client_id='440483442642551',
    client_secret='cd54f1ace848fa2a7ac89a31ed9c1b61',
    name='facebook',
    authorize_url='https://graph.facebook.com/oauth/authorize',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    base_url='https://graph.facebook.com/')

redirect_uri = 'https://www.facebook.com/connect/login_success.html'

params = {'scope': 'read_stream',
          'response_type': 'token',
          'redirect_uri': redirect_uri}

authorize_url = facebook.get_authorize_url(**params)

print 'Visit this URL in your browser: ' + authorize_url
webbrowser.open(authorize_url);

url_with_code = raw_input('Copy URL from your browser\'s address bar: ')
access_token = re.search('\#access_token=([^&]*)', url_with_code).group(1)
session = facebook.get_session(access_token)

user = session.get('me').json()

print 'currently logged in as: ' + user['link']
