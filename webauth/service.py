'''
    webauth.service
    ---------------

    Provides OAuth 1.0/a and 2.0 service containers.
'''

import requests
import json

from webauth.hook import OAuth1Hook

from urllib import quote, urlencode
from urlparse import parse_qsl


def _parse_response(response):
    '''Attempts to coerce response.content into a dictionary.

    :param response: A Requests response object.
    '''
    if isinstance(response.content, str):
        try:
            content = json.loads(response.content)
        except ValueError:
            content = dict(parse_qsl(response.content))
        return content
    # TODO: rather than returning the content in the case of receiving
    # something we can't parse we should probably raise an error
    return response.content


class OAuth2Service(object):
    '''An OAuth 2.0 Service container.

    This class is similar in nature to the OAuth1Service container but does
    not make use of a request's hook. Instead the OAuth 2.0 spec is currently
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
        token = service.get_access_token(code='foobar',
                                         grant_type='authorization_code',
                                         redirect_uri='http://example.com/')
    :param name: The service name.
    :param consumer_key: Client consumer key.
    :param consumer_secret: Client consumer secret.
    :param access_token_url: Access token endpoint.
    :param authorize_url: Authorize endpoint.
    :param access_token: An access token, defaults to None.
    '''
    def __init__(self, name, consumer_key, consumer_secret, access_token_url,
            authorize_url, access_token=None):
        self.name = name

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        self.access_token_url = access_token_url
        self.authorize_url = authorize_url

        self.access_token = None
        if access_token is not None:
            self.access_token = access_token

    def get_authorize_url(self, response_type='code', **params):
        '''Returns a proper authorize URL.

        :param reponse_type: The response type. Defaults to 'code'.
        :param **params: Additional arguments to be added to the request
        querystring.
        '''
        params.update({'response_type': response_type})

        params.update({'client_id': self.consumer_key})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self, grant_type='authorization_code', **data):
        '''Retrieves the access token.

        :param grant_type: The grant type. Deaults to 'authorization_code'.
        :param **data: Arguments to be passed in the body of the request.
        '''
        data.update({'grant_type': grant_type})

        data.update(dict(client_id=self.consumer_key,
                         client_secret=self.consumer_secret))

        response = requests.post(self.access_token_url,
                                 data=data)

        response.raise_for_status()

        return _parse_response(response)

    def request(self, http_method, url, access_token=None, **params):
        '''Sends a request to an OAuth 2.0 endpoint, properly wrapped around
        requests.

        The first time an access token is provided it will be saved on the
        object for convenience.

        :param http_method: A string representation of the HTTP method to be
        used.
        :param url: The resource to be requested.
        :param access_token: The access token as returned by
        :class:`get_access_token`.
        :param **params: Additional arguments to be added to the request
        querystring.
        '''
        if access_token is None and self.access_token is None:
            raise ValueError('Access token must be set!')
        elif access_token is not None:
            self.access_token = access_token

        params.update({'access_token': self.access_token})

        response = requests.request(http_method, url, params=params)

        response.raise_for_status()

        return _parse_response(response)


class OAuth1Service(object):
    '''An OAuth 1.0/a Service container.

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

    At this point it is usually necessary to redirect the client to the
    authorize URI. This URI is retrieved as follows::

        authorize_url = service.get_authorize_url(request_token)

    Once the client has authorized the request it is not possible to retrieve
    an access token. Do so as follows::

        response = service.get_access_token(request_token,
                                            request_token_secret,
                                            http_method='GET')

        # access tokens are returned in the response dictionary
        response['oauth_token']
        response['oauth_key']

    Finally the :class:`get_authenticated_session` method returns a wrapped
    session and can be used once the access token has been made available.
    This provides simple access to the providers endpoints.

    :param name: The service name.
    :param consumer_key: Client consumer key.
    :param consumer_secret: Client consumer secret.
    :param request_token_url: Request token endpoint.
    :param access_token_url: Access token endpoint.
    :param authorize_url: Authorize endpoint.
    :param header_auth: Authenication via header, defauls to False.
    '''
    def __init__(self, name, consumer_key, consumer_secret, request_token_url,
            access_token_url, authorize_url, header_auth=False):
        self.name = name

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # authorization endpoints
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url

        # set to True to use header authentication for this service
        self.header_auth = header_auth

    def _construct_session(self, **kwargs):
        '''Construct the request session, supplying the consumer key and
        secret.

        :param **kwargs: Extra arguments to be passed to the OAuth1Hook
        constructor.
        '''
        hook = OAuth1Hook(consumer_key=self.consumer_key,
                          consumer_secret=self.consumer_secret,
                          **kwargs)
        return requests.session(hooks={'pre_request': hook})

    def get_request_token(self, http_method, **data):
        '''Gets a request token from the request token endpoint.

        :param http_method: A string representation of the HTTP method to be
        used.
        :param **data: Arguments to be passed in the body of the request.
        '''
        auth_session = \
                self._construct_session(header_auth=self.header_auth)

        response = auth_session.request(http_method,
                                        self.request_token_url,
                                        data=data)

        response.raise_for_status()

        data = dict(parse_qsl(response.content))
        return data['oauth_token'], data['oauth_token_secret']

    def get_authorize_url(self, request_token, **params):
        '''Returns a proper authorize URL.

        :param request_token: The request token as returned by
        :class:`get_request_token`.
        :param **params: Additional arguments to be added to the request
        querystring.
        '''
        params.update({'oauth_token': quote(request_token)})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self, request_token, request_token_secret,
                         http_method, **params):
        '''Retrieves the access token.

        :param request_token: The request token as returned by
        :class:`get_request_token`.
        :param request_token_secret: The request token secret as returned by
        :class:`get_request_token`.
        :param http_method: A string representation of the HTTP method to be
        used.
        :param **params: Additional arguments to be added to the request
        querystring.
        '''
        auth_session = self._construct_session(
                                access_token=request_token,
                                access_token_secret=request_token_secret,
                                header_auth=self.header_auth)

        response = auth_session.request(http_method,
                                        self.access_token_url,
                                        params=params)

        response.raise_for_status()

        return _parse_response(response)

    def get_authenticated_session(self, access_token, access_token_secret,
            header_auth=False):
        '''Returns an authenticated Requests session utilizing the hook.

        :param access_token: The access token as returned by
        :class:`get_access_token`
        :param access_token_secret: The access token secret as returned by
        :class:`get_access_token`
        :param header_auth: Authenication via header, defauls to False.
        '''
        return self._construct_session(access_token=access_token,
                                       access_token_secret=access_token_secret,
                                       header_auth=header_auth)

    def request(self, http_method, url, access_token, access_token_secret,
            header_auth=False, params=None, data=None):
        '''Makes a request using :class:`_construct_session`.

        :param http_method: A string representation of the HTTP method to be
        used.
        :param url: The resource to be requested.
        :param access_token: The access token as returned by
        :class:`get_access_token`.
        :param access_token_secret: The access token secret as returned by
        :class:`get_access_token`.
        :param header_auth: Authenication via header, defauls to False.
        :param params: Additional arguments to be added to the request
        querystring.
        :param data: Additional data to be included in the request body.
        '''
        auth_session = \
            self._construct_session(access_token=access_token,
                                    access_token_secret=access_token_secret,
                                    header_auth=header_auth)

        response = auth_session.request(http_method,
                                        url,
                                        params=params,
                                        data=data,
                                        allow_redirects=True)

        response.raise_for_status()

        return _parse_response(response)
