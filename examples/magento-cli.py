#!/usr/bin/env python
# encoding=utf-8

from rauth.service import OAuth1Service

# Create consumer key & secret in your Magento Admin interface
# For an API Guideline see:
# http://www.magentocommerce.com/api/rest/authentication/oauth_authentication.html
#
# Short Magento setup explanation:
# 1. Magento Admin > System > Web Services > REST - OAuth Consumers:
#    Add a new consumer for this script [maybe the OAuth1Service(name='') value]
#    (This creates the consumer_key and consumer_secret token for you)
# 2. Possibly enable rewriting rules for the /api url in the Magento .htaccess
# 3. Magento Admin > System > Web Services > REST - Roles:
#    Give the Customer account some access to stuff (using the customer authorize_url below)
#    or create an Admin account for write access (using the admin authorize_url below)
#    Give the Guest account some access for some basic functionality testing without authorization.
# 4. Magento Admin > System > Web Services > REST - Attributes:
#    Configure ACL attributes access for the role/account configured in 3rd
# -  The customer must have a (frontend) account to login to and authorize the script.
# -  For any created Admin roles in 3rd, the role needs to be mapped to an admin user:
# 5. Magento Admin > System > Permissions > Users:
#    Edit an admin user and under 'REST Role', tick the created Admin REST Role to map it to that account.
#    This admin will get the authorize_url to authorize your script access in the browser.

MAGENTO_HOST = 'http://127.0.0.1'
MAGENTO_API_BASE = '%s/api/rest/' % MAGENTO_HOST

magento = OAuth1Service(
    name               = 'magento',
    consumer_key       = 'vygdq11yzaectqwbpn1h4zwlamsrpomi',
    consumer_secret    = '5x5idvqc8rh4vc8lrxeg4hvple0u63dt',
    request_token_url  = '%s/oauth/initiate' % MAGENTO_HOST,
    access_token_url   = '%s/oauth/token' % MAGENTO_HOST,
    # Customer authorization
    #authorize_url     = MAGENTO_HOST + '%s/oauth/authorize' % MAGENTO_HOST,
    # Admin authorize url depending on admin url
    authorize_url      = '%s/admin/oauth_authorize' % MAGENTO_HOST,
    base_url           = MAGENTO_API_BASE )

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

session.close()
