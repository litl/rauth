'''
    webauth.hook
    ------------

    A hook for the Python Requests package that provides OAuth 1.0/a client
    support.
'''

import time
import random

from hashlib import sha1
from urllib import quote, urlencode

from oauth import HmacSha1Signature, Token, Consumer


class OAuthHook(object):
    '''Primary hook object providing the interface through which a request is
    hooked into and patched.

    This package is built on the excellent Python Requests package. It
    functions by "hooking" into a request and appending various attributes to
    it which allow a client to interact with a standardized OAuth 1.0/a
    provider.

    You might intialize :class:`OAuthHook` something like this::

        oauth = OAuthHook(consumer_key=1234,
                          consumer_secret=5678)
        oauth_session = requests.session(hooks={'pre_request': oauth})

    This establishes a requests session that is wrapped if the OAuth-capable
    hook. Using this session, an OAuth provider may be interacted with and
    will receive the proper formatting for requests.

    Note that this is normally used as a starting from which a request token
    would be generated whereupon an access token is received. Once such a token
    has been received, the wrapper should be reinitalized with this token::

        # we provide our consumer pair as well as the access pair as returned
        # by the provider endpoint
        oauth = OAuthHook(consumer_key=1234,
                          consumer_secret=5678,
                          access_token=4321,
                          access_token_secret=8765)
        oauth_session = requests.session(hooks={'pre_request': oauth})

    The session is now ready to make calls to the endpoints made available by
    the provider.

    Additionally some services will make use of header authentication. This is
    provided by passing :class:`__init__` the `auth_header` parameter as 
    `True`.
    '''
    OAUTH_VERSION = '1.0'
    signature = HmacSha1Signature()
    token = None

    def __init__(self, consumer_key, consumer_secret, access_token=None,
            access_token_secret=None, header_auth=False):
        # construct a token if the access token is available
        if not None in (access_token, access_token_secret):
            self.token = Token(access_token, access_token_secret)

        self.consumer = Consumer(consumer_key, consumer_secret)
        self.header_auth = header_auth

    def __call__(self, request):
        # apparently it's possible for these not to be set?
        if not request.params:
            request.params = {}
        if not request.data:
            request.data = {}

        # this is a workaround for a known bug that will be patched
        if isinstance(request.params, list):
            request.params = dict(request.params)
        if isinstance(request.data, list):
            request.data = dict(request.data)

        # generate the necessary request params
        request.oauth_params = self.generate_oauth_params()

        # here we append an oauth_callback parameter if any
        if 'oauth_callback' in request.data:
            request.oauth_params['oauth_callback'] = \
                    request.data.pop('oauth_callback')
        if 'oauth_callback' in request.params:
            request.oauth_params['oauth_callback'] = \
                    request.params.pop('oauth_callback')

        # this is used in the Normalize Request Parameters step
        request.data_and_params = request.oauth_params.copy()

        # sign and add the signature to the request params
        self.signature.sign(request, self.consumer, self.token)

        if self.header_auth:
            # authenticate in the header
            request.headers['Authorization'] = \
                    self.generate_authorization_header(request.data_and_params)
        elif request.method == 'POST':
            # add data_and_params to the body of the POST
            request.data = request.data_and_params
            request.headers['content-type'] = \
                    'application/x-www-form-urlencoded'
        else:
            # add data_and_params to the URL parameters
            request.url = request.url + '?' + \
                    urlencode(request.data_and_params)

        # we're done with these now
        del request.data_and_params

    def generate_oauth_params(self):
        '''This method handles generating the necessary URL parameters the
        OAuth provider will expect.'''
        oauth_params = {}

        oauth_params['oauth_consumer_key'] = self.consumer.key
        oauth_params['oauth_timestamp'] = int(time.time())
        oauth_params['oauth_nonce'] = sha1(str(random.random())).hexdigest()
        oauth_params['oauth_version'] = self.OAUTH_VERSION

        if self.token:
            oauth_params['oauth_token'] = self.token.key
            # this must be set upon recieving a verifier
            oauth_params['oauth_verifier'] = self.token.verifier or ''

        oauth_params['oauth_signature_method'] = self.signature.NAME
        return oauth_params

    def generate_authorization_header(self, oauth_params):
        '''This method constructs an authorization header.'''
        auth_header = 'OAuth realm=""'
        params = ''
        for k, v in oauth_params.items():
           params += ',{0}="{1}"'.format(k, quote(str(v)))
        auth_header += params
        return auth_header
