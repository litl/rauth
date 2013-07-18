from rauth import OAuth1Service
 
try:
    read_input = raw_input
except NameError:
    read_input = input
 
# Get a real consumer key & secret from https://dev.twitter.com/apps/new
twitter = OAuth1Service(
    name='twitter',
    consumer_key='J8MoJG4bQ9gcmGh8H7XhMg',
    consumer_secret='7WAscbSy65GmiVOvMU5EBYn5z80fhQkcFWSLMJJu4',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    base_url='https://api.twitter.com/1.1/')
 
request_token, request_token_secret = twitter.get_request_token()
 
authorize_url = twitter.get_authorize_url(request_token)
 
print('Visit this URL in your browser: {url}'.format(url=authorize_url))
pin = read_input('Enter PIN from browser: ')
 
session = twitter.get_auth_session(request_token,
                                   request_token_secret,
                                   method='POST',
                                   data={'oauth_verifier': pin})
 
params = {'include_rts': 1,  # Include retweets
          'count': 10}       # 10 tweets
 
r = session.get('statuses/home_timeline.json', params=params, verify=True)
 
for i, tweet in enumerate(r.json(), 1):
    handle = tweet['user']['screen_name']
    text = tweet['text']
    print(u'{0}. @{1} - {2}'.format(i, handle, text))
