from rauth.service import OAuth1Service

linkedin = OAuth1Service(
    consumer_key='tjm826j6uzio',
    consumer_secret='1XbHsC7UxtC6EzqW',
    name='linkedin',
    request_token_url='https://api.linkedin.com/uas/oauth/requestToken',
    authorize_url='https://api.linkedin.com/uas/oauth/authorize',
    access_token_url='https://api.linkedin.com/uas/oauth/accessToken',
    base_url='http://api.linkedin.com/v1/')

request_token, request_token_secret = linkedin.get_request_token()

authorize_url = linkedin.get_authorize_url(request_token)

print 'Visit this URL in your browser: ' + authorize_url
pin = raw_input('Enter PIN from browser: ')

session = linkedin.get_auth_session(request_token,
                                    request_token_secret,
                                    data={'oauth_verifier': pin},
                                    header_auth=True)

r = session.get('people/~/network/updates',
                params={'type': 'SHAR', 'format': 'json'},
                header_auth=True)

updates = r.json()

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
