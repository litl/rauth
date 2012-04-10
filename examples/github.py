from rauth.service import OAuth2Service

# Get a real consumer key & secret from:
# https://github.com/settings/applications/new
github = OAuth2Service(
        name='github',
        authorize_url='https://github.com/login/oauth/authorize',
        access_token_url='https://github.com/login/oauth/access_token',
        consumer_key='8ae4946cc5a9af76f6d7',
        consumer_secret='48aeb2b3c9226ae2b698eef4d7e6310473ccafa7')

print 'Visit this URL in your browser: ' +  github.get_authorize_url()

# This is a bit cumbersome, but you need to copy the code=something out of the
# URL that's redirected to AFTER you login and authorize the demo application
code = raw_input('Enter code parameter (code=something) from URL: ')

# retrieve the access token
access_token = github.get_access_token(
        code=code,
        redirect_uri='https://github.com/litl/rauth/').content['access_token']

# make a request using the access token
user = github.request('GET',
                      'https://github.com/api/v2/json/user/show',
                      access_token=access_token).content['user']

print 'currently logged in as: ' + user['login']
