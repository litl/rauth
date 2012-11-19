from rauth.service import OAuth1Service

LINKEDIN_API_BASE = 'http://api.linkedin.com/v1/'

linkedin = OAuth1Service(
    name='linkedin',
    consumer_key='tjm826j6uzio',
    consumer_secret='1XbHsC7UxtC6EzqW',
    request_token_url='https://api.linkedin.com/uas/oauth/requestToken',
    authorize_url='https://api.linkedin.com/uas/oauth/authorize',
    access_token_url='https://api.linkedin.com/uas/oauth/accessToken',
    header_auth=True)

request_token, request_token_secret = \
    linkedin.get_request_token(method='GET')

authorize_url = linkedin.get_authorize_url(request_token)

print 'Visit this URL in your browser: ' + authorize_url
pin = raw_input('Enter PIN from browser: ')

response = linkedin.get_access_token('POST',
                                     request_token=request_token,
                                     request_token_secret=request_token_secret,
                                     data={'oauth_verifier': pin})

data = response.content

access_token = data['oauth_token']
access_token_secret = data['oauth_token_secret']

response = linkedin.get(
    LINKEDIN_API_BASE + 'people/~/network/updates',
    params={'type': 'SHAR', 'format': 'json'},
    access_token=access_token,
    access_token_secret=access_token_secret)

updates = response.content

for i, update in enumerate(updates['values'], 1):
    if 'currentShare' not in update['updateContent']['person']:
        print '{0}. {1}'.format(i, update['updateKey'])
        continue
    current_share = update['updateContent']['person']['currentShare']
    person = current_share['author']['firstName'].encode('utf-8') + ' '
    person += current_share['author']['lastName'].encode('utf-8')
    comment = current_share.get('comment', '').encode('utf-8')
    if not comment:
        comment = current_share['content']['description'].encode('utf-8')
    print '{0}. {1} - {2}'.format(i, person, comment)
