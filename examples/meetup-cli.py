from rauth import OAuth1Service

# Get a real consumer key & secret from:
# http://www.meetup.com/meetup_api/oauth_consumers/
meetup = OAuth1Service(
    name='meetup',
    consumer_key='bfhkotee222llsjli1v7tf3t0',
    consumer_secret='9uu4vl3236a184nupamwjd3eclb',
    request_token_url='https://api.meetup.com/oauth/request',
    access_token_url='https://api.meetup.com/oauth/access',
    authorize_url='http://www.meetup.com/authorize',
    base_url='https://api.meetup.com/')

request_token, request_token_secret = meetup.get_request_token()

authorize_url = meetup.get_authorize_url(request_token)

# Even though the API documentation says that a pin will be generated
# at authorization_url I did not find this to be the case.
# Once the application is authorized, an authenticated session can be
# retrieved with the same request token and secret used to authorize
print 'Visit this URL in your browser: ' + authorize_url

session = meetup.get_auth_session(request_token,
                                  request_token_secret,
                                  method='POST')

r = session.get('2/member/self', params={'page': '20'})

user = r.json()
name = user['name']
meetup_id = user['id']

print 'Your name is {0} and your member id is {1}'.format(name, meetup_id)


