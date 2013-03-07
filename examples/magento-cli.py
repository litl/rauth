from rauth.service import OAuth1Service

# Create consumer key & secret in your Magento Admin interface
# For an API Guideline see:
# http://www.magentocommerce.com/api/rest/authentication/oauth_authentication.html

magento = OAuth1Service(
    name='magento',
    consumer_key='vygdq11yzaectqwbpn1h4zwlamsrpomi',
    consumer_secret='5x5idvqc8rh4vc8lrxeg4hvple0u63dt',
    request_token_url='http://127.0.0.1/oauth/initiate',
    access_token_url='http://127.0.0.1/oauth/token',
    authorize_url='http://127.0.0.1/oauth/authorize', # Customer authorization
    # Admin authorize url depending on admin url
    #authorize_url='http://127.0.0.1/admin/oauth_authorize', # Admin user authorization
    base_url='http://127.0.0.1/api/rest/')

request_token, request_token_secret = magento.get_request_token(method='POST', params={'oauth_callback': 'oob'})

authorize_url = magento.get_authorize_url(request_token)

print 'Visit this URL in your browser: ' + authorize_url
code = raw_input('Paste Code from browser: ')

session = magento.get_auth_session(request_token,
                                   request_token_secret,
                                   method='POST',
                                   data={'oauth_verifier': code})

headers = {'Accept': 'application/json'}
r = session.get('products', headers=headers)

articles = r.json()

for i, product in articles.items():
    id = product['sku'].encode('utf-8')
    text = product['description'].encode('utf-8')
    print '{0}. ArtNr: {1} - {2}'.format(i, id, text)
