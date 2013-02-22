# -*- coding: utf-8 -*-
'''
    rauth.service
    -------------

    Provides OAuth 1.0/a, 2.0 and Ofly service containers.
'''

from rauth.session import OAuth1Session, OAuth2Session, OflySession
from rauth.utils import absolute_url, parse_utf8_qsl

from urllib import quote, urlencode
from urlparse import urljoin


class HttpMixin(object):
    '''A container for common HTTP request methods.'''
    def get(self, url, **kwargs):
        '''
        Sends a `GET` request.

        :param url: The resource to be requested.
        :type url: str
        :param \*\*kwargs: Optional arguments that :meth:`request` takes.
        :type \*\*\kwargs: dict
        '''
        return self.request('GET', url, **kwargs)

    def options(self, url, **kwargs):
        '''
        Sends a `OPTIONS` request.

        :param url: The resource to be requested.
        :type url: str
        :param \*\*kwargs: Optional arguments that :meth:`request` takes.
        :type \*\*\kwargs: dict
        '''
        return self.request('OPTIONS', url, **kwargs)

    def head(self, url, **kwargs):
        '''
        Sends a `HEAD` request.

        :param url: The resource to be requested.
        :type url: str
        :param \*\*kwargs: Optional arguments that :meth:`request` takes.
        :type \*\*\kwargs: dict
        '''
        return self.request('HEAD', url, **kwargs)

    def post(self, url, **kwargs):
        '''
        Sends a `POST` request.

        :param url: The resource to be requested.
        :type url: str
        :param \*\*kwargs: Optional arguments that :meth:`request` takes.
        :type \*\*\kwargs: dict
        '''
        return self.request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        '''
        Sends a `PUT` request.

        :param url: The resource to be requested.
        :type url: str
        :param \*\*kwargs: Optional arguments that :meth:`request` takes.
        :type \*\*\kwargs: dict
        '''
        return self.request('PUT', url, **kwargs)

    def patch(self, url, **kwargs):
        '''
        Sends a `PATCH` request.

        :param url: The resource to be requested.
        :type url: str
        :param \*\*kwargs: Optional arguments that :meth:`request` takes.
        :type \*\*\kwargs: dict
        '''
        return self.request('PATCH', url, **kwargs)

    def delete(self, url, **kwargs):
        '''
        Sends a `DELETE` request.

        :param url: The resource to be requested.
        :type url: str
        :param \*\*kwargs: Optional arguments that :meth:`request` takes.
        :type \*\*\kwargs: dict
        '''
        return self.request('DELETE', url, **kwargs)


class Service(HttpMixin):
    def __init__(self, name, base_url, authorize_url):
        # the service name, e.g. 'twitter'
        self.name = name

        # the base URL used for making API requests
        self.base_url = base_url

        # the authorization URL
        self.authorize_url = authorize_url

    def request(self, session, method, url, **kwargs):  # pragma: no cover
        url = self._set_url(url)
        return session.request(method, url, **kwargs)

    def _set_url(self, url):
        if self.base_url is not None and not absolute_url(url):
            return urljoin(self.base_url, url)
        return url


class OAuth1Service(Service):
    '''
    An OAuth 1.0/a Service container.

    This class provides a wrapper around a specialized
    :class:`~requests.sessions.Session` object. It exposes a method,
    :meth:`get_session` which produces instances of this class. It also stores
    these instances on :attr:`sessions` where when provided a token pair
    they will be reused on subsequent calls thus allowing for preservation of
    cookies and history amoung other Requests' session object sugar.

    You might intialize :class:`OAuth1Service` something like
    this::

        service = OAuth1Service(
                   name='example',
                   consumer_key='123',
                   consumer_secret='456',
                   request_token_url='http://example.com/request_token',
                   access_token_url='http://example.com/access_token',
                   authorize_url='http://example.com/authorize',
                   base_url='http://example.com/api')

    Now the request token should be retrieved::

        request_token, request_token_secret = service.get_request_token()

    .. admonition:: Differing Request Token Formats

        Some services provide different formatting when returning tokens. For
        this reason the service wrapper provides a special method
        :meth:`get_raw_request_token`. This will return the unparsed response.
        At this point it's up to you to extract the necessary data.

    It's time to access the authorize URI and direct the client to authorize
    requests on their behalf. This URI is retrieved as follows::

        authorize_url = service.get_authorize_url(request_token)

    Once the client has authorized the request it is now possible to retrieve
    an access token. Do so as follows::

        token, token_secret = service.get_access_token(request_token,
                                                       request_token_secret)

    .. admonition:: Differing Access Token Formats

        Some services provide different formatting when returning tokens. For
        this reason the service wrapper provides a special method
        :meth:`get_raw_access_token`. This will return the unparsed response.
        At this point it's up to you to extract the necessary data.

    Finally the service wrapper is now fully ready to make OAuth 1.0/a requests
    against the provider's endpoints. Because Rauth is a wrapper around
    Requests, the same API you would use with Requests is exposed and
    expected::

        r = service.get('some/resource/', params={'format': 'json'})
        print r.json()

    :param consumer_key: Client consumer key, required for signing.
    :type consumer_key: str
    :param consumer_secret: Client consumer secret, required for signing.
    :type consumer_secret: str
    :param name: The service name, defaults to `None`.
    :type name: str
    :param request_token_url: Request token endpoint, defaults to `None`.
    :type request_token_url: str
    :param access_token_url: Access token endpoint, defaults to `None`.
    :type access_token_url: str
    :param authorize_url: Authorize endpoint, defaults to `None`.
    :type authorize_url: str
    :param access_token: An access token, defaults to `None`.
    :type access_token: str
    :param access_token_secret: An access token secret, defaults to `None`.
    :type access_token_secret: str
    :param base_url: A base URL from which to construct requests, defaults to
        `None`.
    :type base_url: str
    :param session_obj: Object used to construct sessions with, defaults to
        :class:`rauth.OAuth1Session <OAuth1Session>`
    :type session_obj: :class:`Session`
    '''
    def __init__(self,
                 consumer_key,
                 consumer_secret,
                 name=None,
                 request_token_url=None,
                 access_token_url=None,
                 authorize_url=None,
                 access_token=None,
                 access_token_secret=None,
                 base_url=None,
                 session_obj=None):

        # client credentials
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # authorization endpoints
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url

        # access tokens
        self.access_token = access_token
        self.access_token_secret = access_token_secret

        # object used to construct sessions with
        self.session_obj = session_obj or OAuth1Session

        # memoized Session objects keyed by access token
        self.sessions = {}

        super(OAuth1Service, self).__init__(name,
                                            base_url,
                                            authorize_url)

    def get_session(self, tokens=None, signature=None):
        '''
        If provided a `tokens` parameter, tries to retrieve a stored
        `rauth.OAuth1Session` instance. Otherwise generates a new session
        instance with the :class:`rauth.OAuth1Service.consumer_key` and
        :class:`rauth.OAuth1Service.consumer_secret` stored on the
        `rauth.OAuth1Service` instance.

        :param tokens: A tuple of tokens with which to memoize the session
            object instance.
        :type tokens: tuple
        '''
        session = self.sessions.get(tokens)
        if session is None:
            if tokens is not None:
                access_token, access_token_secret = tokens
                session = self.session_obj(self.consumer_key,
                                           self.consumer_secret,
                                           access_token,
                                           access_token_secret,
                                           signature,
                                           service=self)
                self.sessions[tokens] = session
            else:
                session = self.session_obj(self.consumer_key,
                                           self.consumer_secret,
                                           signature=signature,
                                           service=self)
        return session

    def get_raw_request_token(self, method='GET', **kwargs):
        '''
        Returns a Requests' response over the
        :attr:`rauth.OAuth1Service.request_token_url`.

        Use this if your endpoint doesn't use the usual names for `oauth_token`
        and `oauth_token_secret`.

        :param method: A string representation of the HTTP method to be used,
            defaults to `GET`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        # ensure we've set the request_token_url
        if self.request_token_url is None:
            raise TypeError('request_token_url must not be None')

        return self.request(method, self.request_token_url, **kwargs)

    def get_request_token(self, method='GET', **kwargs):
        '''
        Return a request token pair.

        :param method: A string representation of the HTTP method to be used,
            defaults to `GET`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        r = self.get_raw_request_token(method=method, **kwargs)
        data = parse_utf8_qsl(r.content)
        return data['oauth_token'], data['oauth_token_secret']

    def get_authorize_url(self, request_token, **params):
        '''
        Returns a formatted authorize URL.

        :param request_token: The request token as returned by
            :class:`get_request_token`.
        :type request_token: str
        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        :type \*\*params: dict
        '''
        params.update({'oauth_token': quote(request_token)})
        return self.authorize_url + '?' + urlencode(params)

    def get_raw_access_token(self,
                             request_token,
                             request_token_secret,
                             method='GET',
                             **kwargs):
        '''
        Returns a Requests' response over the
        :attr:`rauth.OAuth1Service.access_token_url`.

        Use this if your endpoint doesn't use the usual names for `oauth_token`
        and `oauth_token_secret`.

        :param request_token: The request token as returned by
            :meth:`get_request_token`.
        :type request_token: str
        :param request_token_secret: The request token secret as returned by
            :meth:`get_request_token`.
        :type request_token_secret: str
        :param method: A string representation of the HTTP method to be
            used, defaults to `GET`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        # ensure we've set the access_token_url
        if self.access_token_url is None:
            raise TypeError('access_token_url must not be None')

        return self.request(method,
                            self.access_token_url,
                            access_token=request_token,
                            access_token_secret=request_token_secret,
                            **kwargs)

    def get_access_token(self,
                         request_token,
                         request_token_secret,
                         method='GET',
                         **kwargs):
        '''
        Returns an access token pair.

        :param request_token: The request token as returned by
            :meth:`get_request_token`.
        :type request_token: str
        :param request_token_secret: The request token secret as returned by
            :meth:`get_request_token`.
        :type request_token_secret: str
        :param method: A string representation of the HTTP method to be
            used, defaults to `GET`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        r = self.get_raw_access_token(request_token,
                                      request_token_secret,
                                      method=method,
                                      **kwargs)
        data = parse_utf8_qsl(r.content)
        return data['oauth_token'], data['oauth_token_secret']

    def request(self,
                method,
                url,
                access_token=None,
                access_token_secret=None,
                header_auth=False,
                realm=None,
                **kwargs):  # pragma: no cover
        '''
        Sends a request to an OAuth 1.0/a resource.

        :param method: A string representation of the HTTP method to be
            used.
        :type method: str
        :param url: The resource to be requested.
        :type url: str
        :param access_token: The access token as returned by
            :meth:`get_access_token`, defaults to `None`.
        :type access_token: str
        :param access_token_secret: The access token secret as returned by
            :meth:`get_access_token`, defaults to `None`.
        :type access_token_secret: str
        :param header_auth: Authentication via header, defaults to `False`.
        :type header_auth: bool
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        access_tokens = self._parse_access_tokens(access_token,
                                                  access_token_secret)
        session = self.get_session(access_tokens)

        return super(OAuth1Service, self).request(session,
                                                  method,
                                                  url,
                                                  header_auth=header_auth,
                                                  realm=realm,
                                                  **kwargs)

    def _parse_access_tokens(self, access_token, access_token_secret):
        # check user supplied tokens
        access_tokens = (access_token, access_token_secret)
        all_tokens_none = all(v is None for v in access_tokens)
        if None in access_tokens and not all_tokens_none:
            raise TypeError('Either both or neither access_token and '
                            'access_token_secret must be supplied')

        # use default tokens if user supplied tokens are not present
        if all_tokens_none:
            access_token = self.access_token
            access_token_secret = self.access_token_secret

        return access_token, access_token_secret


class OAuth2Service(Service):
    '''
    An OAuth 2.0 Service container.

    This class provides a wrapper around a specialized
    :class:`~requests.session.Session` object. It exposes a method,
    :meth:`rauth.OAuth2Service.get_session` which produces instances of
    :class:`OAuth2Session`. It also stores these instances on an
    attribute :attr:`rauth.OAuth2Service.sessions` where when provided a token
    they will be reused on subsequent calls thus allowing for preservation of
    cookies and history amoung other Requests' session object sugar.

    You might intialize :class:`OAuth2Service` something like this::

        service = OAuth2Service(
                   name='example',
                   client_id='123',
                   client_secret='456',
                   access_token_url='https://example.com/token',
                   authorize_url='https://example.com/authorize',
                   base_url='https://example.com/api')

    Given the simplicity of OAuth 2.0 now this object `service` can be used to
    retrieve an access token in two steps::

        # the return URL is used to validate the request
        url = service.get_authorize_url(redirect_uri='http://example.com/',
                                        params={'response_type': 'code'})

        # once the above URL is consumed by a client we can ask for an access
        # token. note that the code is retrieved from the redirect URL above,
        # as set by the provider
        data = {'code': 'foobar',
                'grant_type': 'authorization_code',
                'redirect_uri': 'http://example.com/'}

        token = service.get_access_token('POST', data=data)

    Now that we have retrieved an access token, we may make requests against
    the OAuth 2.0 provider's endpoints. As much as possible the Requests' API
    is preserved and you may make requests using the same parameters you would
    using Requests::

        r = service.get('some/resource/', params={'format': 'json'})
        print r.json()

    :param client_id: Client id.
    :type client_id: str
    :param client_secret: Client secret.
    :type client_secret: str
    :param name: The service name, defaults to `None`.
    :type name: str
    :param access_token_url: Access token endpoint, defaults to `None`.
    :type access_token_url: str
    :param authorize_url: Authorize endpoint, defaults to `None`.
    :type authorize_url: str
    :param access_token: An access token, defaults to `None`.
    :type access_token: str
    :param base_url: A base URL from which to construct requests, defaults to
        `None`.
    :type base_url: str
    :param session_obj: Object used to construct sessions with, defaults to
        :class:`OAuth2Session`
    :type session_obj: :class:`rauth.Session`
    '''
    def __init__(self,
                 client_id,
                 client_secret,
                 name=None,
                 access_token_url=None,
                 authorize_url=None,
                 access_token=None,
                 base_url=None,
                 session_obj=None):

        # client credentials
        self.client_id = client_id
        self.client_secret = client_secret

        # the provider's access token URL
        self.access_token_url = access_token_url

        # access token
        self.access_token = access_token

        # object used to construct sessions with
        self.session_obj = session_obj or OAuth2Session

        # memoized Session objects, keyed by access token
        self.sessions = {}

        super(OAuth2Service, self).__init__(name,
                                            base_url,
                                            authorize_url)

    def get_session(self, token=None):
        '''
        If provided a `token` parameter, tries to retrieve a stored
        :class:`OAuth2Session` instance. Otherwise generates a new
        session instance with the :attr:`OAuth2Service.client_id` and
        :attr:`OAuth2Service.client_secret` stored on the
        :class:`OAuth2Service` instance.

        :param token: A token with which to memoize the session object
            instance.
        :type token: str
        '''
        session = self.sessions.get(token)
        if session is None:
            if token is not None:
                session = self.session_obj(self.client_id,
                                           self.client_secret,
                                           token,
                                           service=self)
                self.sessions[token] = session
            else:
                session = self.session_obj(self.client_id,
                                           self.client_secret,
                                           service=self)
        return session

    def get_authorize_url(self, **params):
        '''
        Returns a formatted authorize URL.

        :param \*\*params: Additional keyworded arguments to be added to the
            URL querystring.
        :type \*\*params: dict
        '''

        params.update({'client_id': self.client_id})
        return self.authorize_url + '?' + urlencode(params)

    def get_raw_access_token(self, method='POST', **kwargs):
        '''
        Returns a Requests' response over the
        :attr:`OAuth2Service.access_token_url`.

        Use this if your endpoint doesn't use the usual formatting for access
        tokens.

        :param method: A string representation of the HTTP method to be used,
            defaults to `POST`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        key = 'data'
        if 'params' in kwargs:
            key = 'params'

        kwargs.setdefault(key, {})
        kwargs[key].update({'client_id': self.client_id,
                            'client_secret': self.client_secret})

        return self.request(method, self.access_token_url, **kwargs)

    def get_access_token(self, method='POST', **kwargs):
        '''
        Sets the access token on :class:`OAuth2Service` and returns it.

        :param method: A string representation of the HTTP method to be usedd,
            defaults to `POST`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        r = self.get_raw_access_token(method, **kwargs)

        data = parse_utf8_qsl(r.content)

        access_token = data['access_token']
        self.access_token = access_token

        return access_token

    def request(self,
                method,
                url,
                access_token=None,
                **kwargs):  # pragma: no cover
        '''
        Sends a request to an OAuth 2.0 resource.

        :param method: A string representation of the HTTP method to be used.
        :type method: str
        :param url: The resource to be requested.
        :type url: str
        :param access_token: Overrides :class:`access_token` if not None,
            defaults to `None`.
        :type access_token: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        access_token = access_token or self.access_token

        session = self.get_session(access_token)

        return super(OAuth2Service, self).request(session,
                                                  method,
                                                  url,
                                                  **kwargs)


class OflyService(Service):
    '''
    An Ofly Service container.

    This class wraps an Ofly service i.e., Shutterfly. The process
    is similar to that of OAuth 1.0 but simplified.

    You might intialize :class:`OflyService` something like this::

        service = OflyService(name='example',
                              app_id='123',
                              app_secret='456',
                              authorize_url='http://example.com/authorize')

    A signed authorize URL is then produced via calling
    `service.get_authorize_url`. Once this has been visited by the client and
    assuming the client authorizes the request, subsequent API calls may be
    made through `service.request`.

    :param app_id: The oFlyAppId, i.e. "application ID".
    :type app_id: str
    :param app_secret: The oFlyAppSecret, i.e. "shared secret".
    :type app_secret: str
    :param name: The service name, defaults to `None`.
    :type name: str
    :param authorize_url: Authorize endpoint, defaults to `None`.
    :type authorize_url: str
    :param base_url: A base URL from which to construct requests, defaults to
        `None`.
    :type base_url: str
    :param session_obj: Object used to construct sessions with, defaults to
        `rauth.OflySession`
    :type session_obj: :class:`rauth.Session`
    '''
    def __init__(self,
                 app_id,
                 app_secret,
                 name=None,
                 authorize_url=None,
                 base_url=None,
                 session_obj=None):
        # client credentials
        self.app_id = app_id
        self.app_secret = app_secret

        # object used to construct sessions with
        self.session_obj = session_obj or OflySession

        super(OflyService, self).__init__(name,
                                          base_url,
                                          authorize_url)

    def get_session(self):
        '''Generates a new session instance.'''
        return self.session_obj(self.app_id, self.app_secret, self)

    def get_authorize_url(self, **params):
        '''
        Returns a formatted authorize URL.

        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        :type \*\*params: dict
        '''
        params, _ = self.session_obj.sign(self.authorize_url,
                                          self.app_id,
                                          self.app_secret,
                                          **params)
        return self.authorize_url + '?' + params

    def request(self,
                method,
                url,
                header_auth=False,
                hash_meth='sha1',
                **kwargs):  # pragma no cover
        '''
        Sends a request to an Ofly resource.

        :param method: A string representation of the HTTP method to be
            used.
        :type method: str
        :param url: The resource to be requested.
        :type url: str
        :param header_auth: Authentication via header, defaults to False.
        :type header_auth: str
        :params hash_meth: A string representation of the hash method to use
            for signing. Either 'sha1' or 'md5', defaults to 'sha1'.
        :type hash_meth: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        session = self.get_session()

        return super(OflyService, self).request(session,
                                                method,
                                                url,
                                                header_auth=header_auth,
                                                **kwargs)
