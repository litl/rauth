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


class Request(object):
    '''A container for common HTTP request methods.'''
    def head(self, url, **kwargs):
        '''Sends a HEAD request. Returns :class:`Response` object.

        :param url: The resource to be requested.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        '''
        return self.request('HEAD', url, **kwargs)

    def get(self, url, **kwargs):
        '''Sends a GET request. Returns :class:`Response` object.

        :param url: The resource to be requested.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        '''
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        '''Sends a POST request. Returns :class:`Response` object.

        :param url: The resource to be requested.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        '''
        return self.request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        '''Sends a PUT request. Returns :class:`Response` object.

        :param url: The resource to be requested.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        '''
        return self.request('PUT', url, **kwargs)

    def delete(self, url, **kwargs):
        '''Sends a DELETE request. Returns :class:`Response` object.

        :param url: The resource to be requested.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        '''
        return self.request('DELETE', url, **kwargs)


class Service(Request):
    def __init__(self, name, base_url, authorize_url, **kwargs):
        # the service name, e.g. 'twitter'
        self.name = name

        # the base URL used for making API requests
        self.base_url = base_url

        # the authorization URL
        self.authorize_url = authorize_url

        self.__dict__.update(**kwargs)


class OflyService(Service):
    '''An Ofly Service container.

    This class wraps an Ofly service. Most commonly, Shutterfly. The process
    is similar to that of OAuth 1.0 but simplified. Here we use Requests
    directly rather than relying on a hook.

    You might intialize :class:`OflyService` something like this::

        service = OflyService(name='example',
                              app_id='123',
                              app_secret='456',
                              authorize_url='http://example.com/authorize')

    A signed authorize URL is then produced via calling
    `service.get_authorize_url`. Once this has been visited by the client and
    assuming the client authorizes the request, subsequent API calls may be
    made through `service.request`.

    .. admonition:: Additional Signing Options

        The signing process here only supports SHA1 although the specification
        allows for RSA1 as well. This could be implemented in the future. For
        more information please see:
        http://www.shutterfly.com/documentation/OflyCallSignature.sfly

    :param app_id: The oFlyAppId, i.e. "application ID".
    :param app_secret: The oFlyAppSecret, i.e. "shared secret".
    :param name: The service name, defaults to None.
    :param authorize_url: Authorize endpoint, defaults to None.
    :param base_url: A base URL from which to construct requests, defaults to
        None.
    :param session_obj: Object used to construct sessions with, defaults to
        `OflySession`
    '''
    def __init__(self,
                 app_id,
                 app_secret,
                 name=None,
                 authorize_url=None,
                 base_url=None,
                 session_obj=None):
        self.app_id = app_id
        self.app_secret = app_secret

        self.session_obj = session_obj or OflySession

        super(OflyService, self).__init__(name,
                                          base_url,
                                          authorize_url)

    def get_authorize_url(self, **params):
        '''
        Returns a proper authorize URL.

        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        '''
        params = '?' + self.session_obj.sign(self.authorize_url,
                                             self.app_id,
                                             self.app_secret,
                                             **params)
        return self.authorize_url + params

    def request(self, method, url, header_auth=False, **kwargs):
        '''
        Sends a request to an Ofly endpoint, properly wrapped around requests.

        :param method: A string representation of the HTTP method to be
            used.
        :param url: The resource to be requested.
        :param header_auth: Authenication via header, defaults to False.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        if self.base_url is not None and not absolute_url(url):
            url = urljoin(self.base_url, url)

        session = self.session_obj(self.app_id, self.app_secret, self)

        return session.request(method, url, header_auth, **kwargs)


class OAuth2Service(Service):
    '''
    An OAuth 2.0 Service container.

    This class is similar in nature to the OAuth1Service container but does
    not make use of a request hook. Instead the OAuth 2.0 spec is currently
    simple enough that we can wrap it around requests directly.

    You might intialize :class:`OAuth2Service` something like this::

        service = OAuth2Service(
                   name='example',
                   consumer_key='123',
                   consumer_secret='456',
                   access_token_url='http://example.com/token',
                   authorize_url='http://example.com/authorize')

    Given the simplicity of OAuth 2.0 now this object `service` can be used to
    retrieve an access token in two steps::

        # the return URL is used to validate the request
        url = service.get_authorize_url(redirect_uri='http://example.com/',
                                        response_type='code')

        # once the above URL is consumed by a client we can ask for an access
        # token. note that the code is retrieved from the redirect URL above,
        # as set by the provider
        data = dict(code='foobar',
                    grant_type='authorization_code',
                    redirect_uri='http://example.com/')
        token = service.get_access_token('POST', data=data)

    :param client_id: Client id.
    :param client_secret: Client secret.
    :param name: The service name, defaults to None.
    :param access_token_url: Access token endpoint, defaults to None.
    :param authorize_url: Authorize endpoint, defaults to None.
    :param access_token: An access token, defaults to None.
    :param base_url: A base URL from which to construct requests, defaults to
        None.
    :param session_obj: Object used to construct sessions with, defaults to
        `OAuth2Session`
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

        self.client_id = client_id
        self.client_secret = client_secret

        self.access_token_url = access_token_url

        self.access_token = access_token

        self.session_obj = session_obj or OAuth2Session
        self.sessions = {}

        super(OAuth2Service, self).__init__(name,
                                            base_url,
                                            authorize_url,
                                            access_token=access_token)

    def get_session(self, token=None):
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

    def get_authorize_url(self, response_type='code', **params):
        '''
        Returns a proper authorize URL.

        :param reponse_type: The response type. Defaults to 'code'.
        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        '''
        params.update({'client_id': self.client_id,
                       'response_type': response_type})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self, method='POST', **kwargs):
        '''
        Retrieves the access token.

        :param method: A string representation of the HTTP method to be used.
            Defaults to 'POST'.
        :param grant_type: The grant type. Deaults to 'authorization_code'.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        # populate either data or params with our credentials
        key = None
        if 'data' in kwargs:
            key = 'data'
        elif 'params' in kwargs:
            key = 'params'
        else:
            # raise an error because credentials must be sent in this method
            raise NameError('Either params or data dict missing')

        grant_type = kwargs[key].get('grant_type', 'authorization_code')

        # client_credentials flow uses basic authentication for a token
        if grant_type == 'client_credentials':
            kwargs['auth'] = (self.client_id, self.client_secret)
        else:
            kwargs[key].update(client_id=self.client_id,
                               client_secret=self.client_secret,
                               grant_type=grant_type)

        r = self.request(method, self.access_token_url, **kwargs)
        data = parse_utf8_qsl(r.content)

        access_token = data.get('access_token')
        if access_token is not None:
            self.access_token = access_token

        return data

    def request(self, method, url, access_token=None, **kwargs):
        '''
        Sends a request to an OAuth 2.0 endpoint, properly wrapped around
        requests.

        :param method: A string representation of the HTTP method to be used.
        :param url: The resource to be requested.
        :param access_token: Overrides self.access_token. Defaults to None.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''

        # see if we can prepend base_url
        if self.base_url is not None and not absolute_url(url):
            url = urljoin(self.base_url, url)

        access_token = access_token or self.access_token

        session = self.get_session(access_token)
        return session.request(method, url, **kwargs)


class OAuth1Service(Service):
    '''
    An OAuth 1.0/a Service container.

    This class provides a container for an OAuth Service provider. It utilizes
    the OAuthHook object which in turn is hooked into Python Requests. This
    object can be used to streamline the process of authenticating with and
    using an OAuth 1.0/a service provider.

    You might intialize :class:`OAuth1Service` something like this::

        service = OAuth1Service(
                   name='example',
                   consumer_key='123',
                   consumer_secret='456',
                   request_token_url='http://example.com/request_token',
                   access_token_url='http://example.com/access_token',
                   authorize_url='http://example.com/authorize')

    Now the request token should be retrieved::

        request_token, request_token_secret = service.get_request_token()

    Some services provide different formatting when returning tokens. For this
    reason the service wrapper provides a special method
    :class:`get_raw_request_token`. This will return the unparsed response. At
    this point it's up to you to extract the necessary data.

    Now it's time to access the authorize URI and direct the client to
    authorize requests on their behalf. This URI is retrieved as follows::

        authorize_url = service.get_authorize_url(request_token)

    Once the client has authorized the request it is now possible to retrieve
    an access token. Do so as follows::

        response = \
            service.get_access_token(method='GET'
                                     request_token=request_token,
                                     request_token_secret=request_token_secret)

        # access tokens are returned in the response.content dictionary
        response.content['oauth_token']
        response.content['oauth_key']

    Finally the :class:`get_authenticated_session` method returns a wrapped
    session and can be used once the access token has been made available.
    This provides simple access to the providers endpoints.

    :param consumer_key: Client consumer key, required for signing.
    :param consumer_secret: Client consumer secret, required for signing.
    :param name: The service name, defaults to None.
    :param request_token_url: Request token endpoint, defaults to None.
    :param access_token_url: Access token endpoint, defaults to None.
    :param authorize_url: Authorize endpoint, defaults to None.
    :param access_token: An access token, defaults to None.
    :param access_token_secret: An access token secret, defaults to None.
    :param base_url: A base URL from which to construct requests, defaults to
        None.
    :param session_obj: Object used to construct sessions with, defaults to
        `OAuth1Session`
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

        params = dict(access_token=access_token,
                      access_token_secret=access_token_secret)

        # object used to construct sessions with
        self.session_obj = session_obj or OAuth1Session

        # memoized Session objects keyed by access token
        self.sessions = {}

        super(OAuth1Service, self).__init__(name,
                                            base_url,
                                            authorize_url,
                                            **params)

    def get_session(self, tokens=None, signature=None):
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
        Gets a response from the request token endpoint.

        Returns the entire parsed response, without trying to pull out the
        token and secret.  Use this if your endpoint doesn't use the usual
        names for 'oauth_token' and 'oauth_token_secret'.

        :param method: A string representation of the HTTP method to be used.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        # ensure we've set the request_token_url
        if self.request_token_url is None:
            raise TypeError('request_token_url must not be None')

        kwargs.setdefault('params', {'oauth_callback': 'oob'})

        r = self.request(method, self.request_token_url, **kwargs)

        return parse_utf8_qsl(r.content)

    def get_request_token(self, method='GET', **kwargs):
        '''
        Gets a request token from the request token endpoint.

        :param method: A string representation of the HTTP method to be used.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        data = self.get_raw_request_token(method=method, **kwargs)
        return data['oauth_token'], data['oauth_token_secret']

    def get_authorize_url(self, request_token, **params):
        '''
        Returns a proper authorize URL.

        :param request_token: The request token as returned by
            :class:`get_request_token`.
        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        '''
        params.update({'oauth_token': quote(request_token)})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self,
                         request_token,
                         request_token_secret,
                         method='GET',
                         **kwargs):
        '''
        Retrieves the access token pair.

        :param request_token: The request token as returned by
            :class:`get_request_token`.
        :param request_token_secret: The request token secret as returned by
            :class:`get_request_token`.
        :param method: A string representation of the HTTP method to be
            used. Defaults to 'GET'.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        # ensure we've set the access_token_url
        if self.access_token_url is None:
            raise TypeError('access_token_url must not be None')

        r = self.request(method,
                         self.access_token_url,
                         access_token=request_token,
                         access_token_secret=request_token_secret,
                         **kwargs)

        return parse_utf8_qsl(r.content)

    def request(self,
                method,
                url,
                access_token=None,
                access_token_secret=None,
                header_auth=False,
                **kwargs):
        '''
        Makes a proper OAuth 1.0/a request.

        :param method: A string representation of the HTTP method to be
            used.
        :param url: The resource to be requested.
        :param access_token: The access token as returned by
            :class:`get_access_token`. Defaults to None.
        :param access_token_secret: The access token secret as returned by
            :class:`get_access_token`. Defaults to None.
        :param header_auth: Authenication via header, defaults to False.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        # prepend a base_url to the uri if we can
        if self.base_url is not None and not absolute_url(url):
            url = urljoin(self.base_url, url)

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

        session = self.get_session(access_tokens)

        return session.request(method, url, header_auth=header_auth, **kwargs)
