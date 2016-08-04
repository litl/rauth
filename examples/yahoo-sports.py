from rauth import OAuth1Service

try:
	read_input = raw_input
except NameError:
	read_input = input

# get a real consumer key and secret from yahoo
# http://developer.yahoo.com/oauth/
OAUTH_CONSUMER_KEY = ''
OAUTH_SHARED_SECRET = ''

yahoo = OAuth1Service(
	consumer_key=OAUTH_CONSUMER_KEY,
	consumer_secret=OAUTH_SHARED_SECRET,
	name='yahoo',
	access_token_url='https://api.login.yahoo.com/oauth/v2/get_token',
	authorize_url='https://api.login.yahoo.com/oauth/v2/request_auth',
	request_token_url='https://api.login.yahoo.com/oauth/v2/get_request_token',
	base_url='https://api.login.yahoo.com/oauth/v2/')

request_token, request_token_secret = yahoo.get_request_token(data = { 'oauth_callback': "http://example.com/callback/" })
print "Request Token:"
print "    - oauth_token        = %s" % request_token
print "    - oauth_token_secret = %s" % request_token_secret
print

auth_url = yahoo.get_authorize_url(request_token)

print 'Visit this URL in your browser: ' + auth_url
pin = raw_input('Enter PIN from browser: ')

session = yahoo.get_auth_session(request_token, request_token_secret, method='POST', data={'oauth_verifier': pin})

r = session.get(
	'http://fantasysports.yahooapis.com/fantasy/v2/game/nfl')

print r.text