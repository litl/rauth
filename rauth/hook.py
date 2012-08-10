'''
    rauth.hook
    ----------

    A hook for the Python Requests package that provides OAuth 1.0/a client
    support.
'''

import time
import random

from hashlib import sha1
from urlparse import parse_qsl, urlsplit, urlunsplit
from urllib import quote, urlencode

from rauth.oauth import HmacSha1Signature


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
    :param header_auth: Authenication via header, defaults to False.
    :param signature: A signature method used to sign request parameters.
        Defaults to None. If None the `HmacSha1Signature` method is used as
        default.
    :param default_oauth_callback: Defining OAuth callback *is required* (only)
        when obtaining a request token. If `oauth_callback` is not specified
        otherwise (in URL query or body data params), `default_oauth_callback`
        shall be used. In all non-request-token requests it can be left out.
    '''
    OAUTH_VERSION = '1.0'

    oauth_callback = None
    oauth_verifier = None

    def __init__(self, consumer_key, consumer_secret, access_token=None,
                 access_token_secret=None, header_auth=False, signature=None,
                 default_oauth_callback=None):
        # consumer credentials
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # access token credentials
        self.access_token = access_token
        self.access_token_secret = access_token_secret

        self.header_auth = header_auth

        self.signature = HmacSha1Signature()

        # override the default signature object if available
        if signature is not None:
            self.signature = signature

        # 'oauth_callback' is required only on request-token requests
        self.oauth_callback = default_oauth_callback

    def __call__(self, request):
        # this is a workaround for a known bug that will be patched
        if isinstance(request.params, list):
            request.params = dict(request.params)
        if isinstance(request.data, list):
            request.data = dict(request.data)

        # parse optional oauth parameters
        for param in ('oauth_callback', 'oauth_verifier'):
            self._parse_optional_param(param, request)

        # generate the necessary request params
        request.oauth_params = self.oauth_params

        # this is used in the Normalize Request Parameters step
        request.params_and_data = request.oauth_params.copy()

        # sign and add the signature to the request params
        request.oauth_params['oauth_signature'] = \
            self.signature.sign(request,
                                self.consumer_secret,
                                self.access_token_secret)

        request.params_and_data['oauth_signature'] = \
            request.oauth_params['oauth_signature']

        if self.header_auth:
            # extract the domain for use as the realm
            scheme, netloc, _, _, _ = urlsplit(request.url)
            realm = urlunsplit((scheme, netloc, '/', '', ''))

            request.headers['Authorization'] = \
                self.auth_header(request.oauth_params, realm=realm)
        elif request.method == 'POST':
            content_type = 'application/x-www-form-urlencoded'
            request.headers['content-type'] = content_type
            request.data = request.params_and_data
        else:
            request.params = request.params_and_data

        # we're done with these now
        del request.params_and_data

    def _parse_optional_param(self, oauth_param, request):
        '''Parses and sets optional oauth parameters on a request.

        :param oauth_param: The OAuth parameter to parse.
        :param request: The Request object.
        '''
        params_is_string = type(request.params) == str
        data_is_string = type(request.data) == str
        params = request.params
        data = request.data

        # special handling if we're handed a string
        if params_is_string:
            params = dict(parse_qsl(request.params))

        # remove any oauth parameters and set them as attributes
        if oauth_param in params.keys():
            setattr(self, oauth_param, params.pop(oauth_param))
        if not data_is_string and oauth_param in data.keys():
            setattr(self, oauth_param, data.pop(oauth_param))

        # re-encode the params if they were a string, without any oauth
        if params_is_string:
            request.params = urlencode(params)

    @property
    def oauth_params(self):
        '''This method handles generating the necessary URL parameters the
        OAuth provider will expect.'''
        oauth_params = {}

        oauth_params['oauth_consumer_key'] = self.consumer_key
        oauth_params['oauth_timestamp'] = int(time.time())
        oauth_params['oauth_nonce'] = sha1(str(random.random())).hexdigest()
        oauth_params['oauth_version'] = self.OAUTH_VERSION

        if self.access_token is not None:
            oauth_params['oauth_token'] = self.access_token

        if self.oauth_verifier is not None:
            oauth_params['oauth_verifier'] = self.oauth_verifier

        if self.oauth_callback is not None:
            oauth_params['oauth_callback'] = self.oauth_callback

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
