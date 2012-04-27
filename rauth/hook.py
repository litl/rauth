'''
    rauth.hook
    ----------

    A hook for the Python Requests package that provides OAuth 1.0/a client
    support.
'''

import time
import random

from hashlib import sha1
from urllib import quote

from rauth.oauth import HmacSha1Signature, Token, Consumer


class OAuth1Hook(object):
    '''Provides a pre-request hook into requests for OAuth 1.0/a services.

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

    :param consumer_key: Client consumer key.
    :param consumer_secret: Client consumer secret.
    :param access_token: Access token key.
    :param access_token_secret: Access token secret.
    :param header_auth: Authenication via header, defauls to False.
    :param signature: A signature method used to sign request parameters.
        Defaults to None. If None the `HmacSha1Signature` method is used as
        default.
    '''
    OAUTH_VERSION = '1.0'

    def __init__(self, consumer_key, consumer_secret, access_token=None,
            access_token_secret=None, header_auth=False, signature=None):
        self.consumer = Consumer(consumer_key, consumer_secret)

        # intitialize the token and then set it if possible
        self.token = None
        if not None in (access_token, access_token_secret):
            self.token = Token(access_token, access_token_secret)

        self.header_auth = header_auth

        self.signature = HmacSha1Signature()

        # override the default signature object if available
        if signature is not None:
            self.signature = signature

    def __call__(self, request):
        # this is a workaround for a known bug that will be patched
        if isinstance(request.params, list):
            request.params = dict(request.params)
        if isinstance(request.data, list):
            request.data = dict(request.data)

        # generate the necessary request params
        request.oauth_params = self.oauth_params

        # here we append an oauth_callback parameter if any
        if 'oauth_callback' in request.data:
            request.oauth_params['oauth_callback'] = \
                    request.data.pop('oauth_callback')
        if 'oauth_callback' in request.params:
            request.oauth_params['oauth_callback'] = \
                    request.params.pop('oauth_callback')

        # this is used in the Normalize Request Parameters step
        request.params_and_data = request.oauth_params.copy()

        # sign and add the signature to the request params
        self.signature.sign(request, self.consumer, self.token)

        if self.header_auth:
            # authenticate in the header
            #
            # TODO: implement the realm parameter
            request.headers['Authorization'] = \
                    self.auth_header(request.params_and_data)
        elif request.method == 'POST':
            # HACK: override the param encoding process
            #
            # BUG: body can't be recalculated in a pre-request hook; this is a
            # known issue: https://github.com/kennethreitz/requests/issues/445
            #request.data, request._enc_data = \
            #        request._encode_params(request.params_and_data)
            #request.body = request._enc_data
            #request.headers['Content-Type'] = \
            #        'application/x-www-form-urlencoded'
            sig = request.params_and_data['oauth_signature']
            request.oauth_params.update(oauth_signature=sig)
            request.params, request._enc_params = \
                    request._encode_params(request.oauth_params)
        else:
            # HACK: override the param encoding process
            request.params, request._enc_params = \
                    request._encode_params(request.params_and_data)

        # we're done with these now
        del request.params_and_data

    @property
    def oauth_params(self):
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

    def auth_header(self, oauth_params, realm=None):
        '''This method constructs an authorization header.

        :param oauth_params: The OAuth parameters to be added to the header.
        :param realm: The authentication realm. Defaults to None.
        '''
        auth_header = 'OAuth realm="{0}"'.format(realm)
        params = ''
        for k, v in oauth_params.items():
            params += ',{0}="{1}"'.format(k, quote(str(v)))
        auth_header += params
        return auth_header
