# -*- coding: utf-8 -*-
'''
    rauth.session
    -------------

    Specially wrapped Requests' :class:`~request.sessions.Session` objects.
'''

from datetime import datetime
from hashlib import sha1, md5
from random import random
from time import time
from urllib import quote
from urlparse import parse_qsl, urlsplit

from rauth.oauth import HmacSha1Signature
from rauth.utils import FORM_URLENCODED, get_sorted_params

from requests.sessions import Session

OAUTH1_DEFAULT_TIMEOUT = OAUTH2_DEFAULT_TIMEOUT = OFLY_DEFAULT_TIMEOUT = 300.0


class RauthSession(Session):
    def __init__(self, service):
        # a back reference to a service wrapper, if we're using one
        self.service = service
        super(RauthSession, self).__init__()


class OAuth1Session(RauthSession):
    '''
    A specialized :class:`~requests.sessions.Session` object, wrapping OAuth
    1.0/a logic.

    This object is utilized by the :class:`OAuth1Service` wrapper but can
    be used independently of that infrastructure. Essentially this is a loose
    wrapping around the standard Requests codepath. State may be tracked at
    this layer, especially if the instance is kept around and tracked via some
    unique identifier, e.g. access tokens. Things like request cookies will be
    preserved between requests and in fact all functionality provided by
    a Requests' :class:`~requests.sessions.Session` object should be exposed
    here.

    If you were to use this object by itself you could do so by instantiating
    it like this::

        session = OAuth1Session('123',
                                '456',
                                access_token='321',
                                access_token_secret'654')

    You now have a session object which can be used to make requests exactly as
    you would with a normal Requests' :class:`~requests.sessions.Session`
    instance. This anticipates that the standard OAuth 1.0/a flow will be
    modeled outside of the scope of this class. In other words, if the fully
    qualified flow is useful to you then this object probably need not be used
    directly, instead consider using :class:`OAuth1Service`.

    Once the session object is setup, you may start making requests::

        r = session.get('http://example/com/api/resource',
                        params={'format': 'json'})
        print r.json()

    :param consumer_key: Client consumer key.
    :type consumer_key: str
    :param consumer_secret: Client consumer secret.
    :type consumer_secret: str
    :param access_token: Access token, defaults to `None`.
    :type access_token: str
    :param access_token_secret: Access token secret, defaults to `None`.
    :type access_token_secret: str
    :param signature: A signature producing object, defaults to
        :class:`rauth.oauth.HmacSha1Signature`.
    :type signature: :class:`rauth.oauth.Signature`
    :param service: A back reference to the service wrapper, defaults to
        `None`.
    :type service: :class:`rauth.Service`
    '''
    VERSION = '1.0'

    def __init__(self,
                 consumer_key,
                 consumer_secret,
                 access_token=None,
                 access_token_secret=None,
                 signature=None,
                 service=None):

        # consumer credentials
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # access token credentials
        self.access_token = access_token
        self.access_token_secret = access_token_secret

        # signing method
        if signature is None:
            self.signature = HmacSha1Signature()

        super(OAuth1Session, self).__init__(service)

    def request(self,
                method,
                url,
                header_auth=False,
                realm='',
                **req_kwargs):
        '''
        A loose wrapper around Requests' :class:`~requests.sessions.Session`
        which injects OAuth 1.0/a parameters.

        :param method: A string representation of the HTTP method to be used.
        :type method: str
        :param url: The resource to be requested.
        :type url: str
        :param header_auth: Authentication via header, defaults to `False.`
        :type header_auth: bool
        :param realm: The auth header realm, defaults to `''`.
        :type realm: str
        :param \*\*req_kwargs: Keyworded args to be passed down to Requests.
        :type \*\*req_kwargs: dict
        '''
        req_kwargs.setdefault('headers', {})

        # inline query string conversion
        if isinstance(req_kwargs.get('params'), basestring):
            req_kwargs['params'] = dict(parse_qsl(req_kwargs['params']))

        if isinstance(req_kwargs.get('data'), basestring):
            req_kwargs['data'] = dict(parse_qsl(req_kwargs['data']))

        # HACK: Some providers redirect to other domains but expect signing
        # against the first domain, i.e. Photobucket. Here we store the first
        # URL we recieved before redirecting. We also store the request
        # arguments as those may be lost in the redirect process.
        if not 'x-rauth-root-url' in req_kwargs['headers']:
            req_kwargs['headers'].update({'x-rauth-root-url': url})

        if not 'x-rauth-params-data' in req_kwargs['headers']:
            p, d = req_kwargs.get('params', {}), req_kwargs.get('data', {})
            req_kwargs['headers'].update({'x-rauth-params-data': (p, d)})

        post_or_put = method.upper() in ('POST', 'PUT')
        if post_or_put:
            req_kwargs['headers'].setdefault('Content-Type', FORM_URLENCODED)

        req_kwargs.setdefault('timeout', OAUTH1_DEFAULT_TIMEOUT)

        # set the OAuth params on the oauth_params attribute
        self._set_oauth_params()

        # parse optional OAuth parameters
        for param in ('oauth_callback', 'oauth_verifier', 'oauth_version'):
            self._parse_optional_params(param, req_kwargs)

        # sign the request
        self.oauth_params['oauth_signature'] = self.signature.sign(self,
                                                                   method,
                                                                   req_kwargs)

        if header_auth:
            req_kwargs['headers'].update({'Authorization':
                                          self._get_auth_header(realm)})
        elif post_or_put:
            req_kwargs.setdefault('data', {})
            req_kwargs['data'].update(self.__dict__.pop('oauth_params'))
        else:
            req_kwargs.setdefault('params', {})
            req_kwargs['params'].update(self.__dict__.pop('oauth_params'))

        return super(OAuth1Session, self).request(method, url, **req_kwargs)

    def _parse_optional_params(self, oauth_param, req_kwargs):
        '''
        Parses and sets optional OAuth parameters on a request.

        :param oauth_param: The OAuth parameter to parse.
        :type oauth_param: str
        :param req_kwargs: The keyworded arguments passed to the request
            method.
        :type req_kwargs: dict
        '''
        params = req_kwargs.get('params', {})
        data = req_kwargs.get('data', {})

        if oauth_param in params:
            self.oauth_params[oauth_param] = params.pop(oauth_param)
        if oauth_param in data:
            self.oauth_params[oauth_param] = data.pop(oauth_param)

        if params:
            req_kwargs['params'] = params

        if data:
            req_kwargs['data'] = data

    def _set_oauth_params(self):
        '''Prepares OAuth params for signing.'''
        self.oauth_params = {}

        self.oauth_params['oauth_consumer_key'] = self.consumer_key
        self.oauth_params['oauth_nonce'] = sha1(str(random())).hexdigest()
        self.oauth_params['oauth_signature_method'] = self.signature.NAME
        self.oauth_params['oauth_timestamp'] = int(time())

        if self.access_token is not None:
            self.oauth_params['oauth_token'] = self.access_token

        self.oauth_params['oauth_version'] = self.VERSION

    def _get_auth_header(self, realm=None):
        '''Constructs and returns an authentication header.'''
        oauth_params = self.__dict__.pop('oauth_params')
        auth_header = 'OAuth realm="{realm}"'.format(realm=realm or '')
        params = ''
        for k, v in oauth_params.items():
            params += ',{key}="{value}"'.format(key=k, value=quote(str(v)))
        auth_header += params
        return auth_header


class OAuth2Session(RauthSession):
    '''
    A specialized :class:`~requests.sessions.Session` object, wrapping OAuth
    2.0 logic.

    This object is utilized by the :class:`OAuth2Service` wrapper but can
    be used independently of that infrastructure. Essentially this is a loose
    wrapping around the standard Requests codepath. State may be tracked at
    this layer, especially if the instance is kept around and tracked via some
    unique identifier, e.g. access token. Things like request cookies will be
    preserved between requests and in fact all functionality provided by
    a Requests' :class:`~requests.sessions.Session` object should be exposed
    here.

    If you were to use this object by itself you could do so by instantiating
    it like this::

        session = OAuth2Session('123', '456', access_token='321')

    You now have a session object which can be used to make requests exactly as
    you would with a normal Requests :class:`~requests.sessions.Session`
    instance. This anticipates that the standard OAuth 2.0 flow will be modeled
    outside of the scope of this class. In other words, if the fully qualified
    flow is useful to you then this object probably need not be used directly,
    instead consider using :class:`OAuth2Service`.

    Once the session object is setup, you may start making requests::

        r = session.get('https://example/com/api/resource',
                        params={'format': 'json'})
        print r.json()

    :param client_id: Client id.
    :type client_id: str
    :param client_secret: Client secret.
    :type client_secret: str
    :param access_token: Access token, defaults to `None`.
    :type access_token: str
    :param signature: A signature producing object, defaults to
        :class:`rauth.oauth.HmacSha1Signature`.
    :type signature: :class:`rauth.oauth.Signature`
    :param service: A back reference to the service wrapper, defaults to
        `None`.
    :type service: :class:`rauth.Service`
    '''
    def __init__(self,
                 client_id,
                 client_secret,
                 access_token=None,
                 service=None):
        self.client_id = client_id
        self.client_secret = client_secret

        self.access_token = access_token

        super(OAuth2Session, self).__init__(service)

    def request(self, method, url, **req_kwargs):
        '''
        A loose wrapper around Requests' :class:`~requests.sessions.Session`
        which injects OAuth 2.0 parameters.

        :param method: A string representation of the HTTP method to be used.
        :type method: str
        :param url: The resource to be requested.
        :type url: str
        :param \*\*req_kwargs: Keyworded args to be passed down to Requests.
        :type \*\*req_kwargs: dict
        '''
        req_kwargs.setdefault('params', {})

        if isinstance(req_kwargs['params'], basestring):
            req_kwargs['params'] = dict(parse_qsl(req_kwargs['params']))

        req_kwargs['params'].update({'access_token': self.access_token})
        req_kwargs.setdefault('timeout', OAUTH2_DEFAULT_TIMEOUT)

        return super(OAuth2Session, self).request(method, url, **req_kwargs)


class OflySession(RauthSession):
    '''
    A specialized :class:`~requests.sessions.Session` object, wrapping Ofly
    logic.

    This object is utilized by the :class:`OflyService` wrapper
    but can be used independently of that infrastructure. Essentially this is a
    loose wrapping around the standard Requests codepath. State may be tracked
    at this layer, especially if the instance is kept around and tracked via
    some unique identifier. Things like request cookies will be preserved
    between requests and in fact all functionality provided by a Requests'
    :class:`~requests.sessions.Session` object should be exposed here.

    If you were to use this object by itself you could do so by instantiating
    it like this::

        session = OflySession('123', '456')

    You now have a session object which can be used to make requests exactly as
    you would with a normal Requests :class:`~requests.sessions.Session`
    instance. This anticipates that the standard Ofly flow will be modeled
    outside of the scope of this class. In other words, if the fully qualified
    flow is useful to you then this object probably need not be used directly,
    instead consider using :class:`OflyService`.

    Once the session object is setup, you may start making requests::

        r = session.get('https://example/com/api/resource',
                        params={'format': 'json'})
        print r.json()

    :param app_id: The oFlyAppId, i.e. "application ID".
    :type app_id: str
    :param app_secret: The oFlyAppSecret, i.e. "shared secret".
    :type app_secret: str
    :param service: A back reference to the service wrapper, defaults to
        `None`.
    :type service: :class:`rauth.Service`
    '''
    def __init__(self,
                 app_id,
                 app_secret,
                 service=None):
        self.app_id = app_id
        self.app_secret = app_secret

        super(OflySession, self).__init__(service)

    def request(self,
                method,
                url,
                hash_meth='sha1',
                **req_kwargs):
        '''
        A loose wrapper around Requests' :class:`~requests.sessions.Session`
        which injects Ofly parameters.

        :param method: A string representation of the HTTP method to be used.
        :type method: str
        :param url: The resource to be requested.
        :type url: str
        :param hash_meth: The hash method to use for signing, defaults to
            "sha1".
        :type hash_meth: str
        :param \*\*req_kwargs: Keyworded args to be passed down to Requests.
        :type \*\*req_kwargs: dict
        '''
        req_kwargs.setdefault('params', {})
        req_kwargs.setdefault('timeout', OFLY_DEFAULT_TIMEOUT)

        if isinstance(req_kwargs['params'], basestring):
            req_kwargs['params'] = dict(parse_qsl(req_kwargs['params']))

        params = OflySession.sign(url,
                                  self.app_id,
                                  self.app_secret,
                                  hash_meth=hash_meth,
                                  **req_kwargs['params'])

        req_kwargs['params'] = params

        return super(OflySession, self).request(method, url, **req_kwargs)

    @staticmethod
    def sign(url, app_id, app_secret, hash_meth='sha1', **params):
        '''
        A signature method which generates the necessary Ofly parameters.

        :param app_id: The oFlyAppId, i.e. "application ID".
        :type app_id: str
        :param app_secret: The oFlyAppSecret, i.e. "shared secret".
        :type app_secret: str
        :param hash_meth: The hash method to use for signing, defaults to
            "sha1".
        :type hash_meth: str
        :param \*\*params: Additional parameters.
        :type \*\*\params: dict
        '''
        hash_meth_str = hash_meth
        if hash_meth == 'sha1':
            hash_meth = sha1
        elif hash_meth == 'md5':
            hash_meth = md5
        else:
            raise TypeError('hash_meth must be one of "sha1", "md5"')

        now = datetime.utcnow()
        milliseconds = now.microsecond / 1000

        time_format = '%Y-%m-%dT%H:%M:%S.{0}Z'.format(milliseconds)
        ofly_params = {'oflyAppId': app_id,
                       'oflyHashMeth': hash_meth_str.upper(),
                       'oflyTimestamp': now.strftime(time_format)}

        url_path = urlsplit(url).path

        signature_base_string = app_secret + url_path + '?'
        if len(params):
            signature_base_string += get_sorted_params(params) + '&'
        signature_base_string += get_sorted_params(ofly_params)

        ofly_params['oflyApiSig'] = \
            hash_meth(signature_base_string).hexdigest()

        all_params = dict(ofly_params.items() + params.items())

        return get_sorted_params(all_params)
