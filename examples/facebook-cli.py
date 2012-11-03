from rauth.service import OAuth2Service
import re
import webbrowser

# Get a real consumer key & secret from:
# https://developers.facebook.com/apps

facebook = OAuth2Service(
    name='facebook',
    authorize_url='https://graph.facebook.com/oauth/authorize',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    base_url='https://graph.facebook.com/',
    consumer_key='YOUR_CONSUMER_KEY',
    consumer_secret='YOUR_CONSUMER_SECRET')

redirect_uri = 'https://www.facebook.com/connect/login_success.html'
authorize_url = facebook.get_authorize_url(redirect_uri=redirect_uri,
                                           scope='read_stream',
                                           response_type='token')

print 'Visit this URL in your browser: ' + authorize_url
webbrowser.open(authorize_url);

url_with_code = raw_input("Copy URL from your browser's address bar: ")
facebook.access_token = re.search('\#access_token=([^&]*)', url_with_code).group(1)

user = facebook.get('me').content

print 'currently logged in as: ' + user['link']

