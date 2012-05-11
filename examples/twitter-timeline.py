from rauth.service import OAuth1Service

# Get a real consumer key & secret from https://dev.twitter.com/apps/new
twitter = OAuth1Service(
    name='twitter',
    consumer_key='J8MoJG4bQ9gcmGh8H7XhMg',
    consumer_secret='7WAscbSy65GmiVOvMU5EBYn5z80fhQkcFWSLMJJu4',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize')

request_token, request_token_secret = \
    twitter.get_request_token(method='GET')

authorize_url = twitter.get_authorize_url(request_token)

print 'Visit this URL in your browser: ' + authorize_url
pin = raw_input('Enter PIN from browser: ')

response = twitter.get_access_token('POST',
                                    request_token=request_token,
                                    request_token_secret=request_token_secret,
                                    data={'oauth_verifier': pin})
data = response.content

access_token = data['oauth_token']
access_token_secret = data['oauth_token_secret']

params = {'include_rts': 1,  # Include retweets
          'count': 10}       # 10 tweets

response = twitter.get('https://api.twitter.com/1/statuses/home_timeline.json',
                       params=params,
                       access_token=access_token,
                       access_token_secret=access_token_secret,
                       header_auth=True)

for i, tweet in enumerate(response.content, 1):
    handle = tweet['user']['screen_name'].encode('utf-8')
    text = tweet['text'].encode('utf-8')
    print '{0}. @{1} - {2}'.format(i, handle, text)
