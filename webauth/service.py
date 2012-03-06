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
    if isinstance(response.content, str):
        try:
            content = json.loads(response.content)
        except ValueError:
            content = dict(parse_qsl(response.content))
        return content
    return response.content


class OAuth2Service(object):
    '''An OAuth 2.0 Service container.'''
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

    def get_authorize_url(self, **params):
        '''Returns a proper authorize URL.'''
        params.update({'client_id': self.consumer_key})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self, code, **data):
        '''Retrieves the access token.'''
        data.update(dict(client_id=self.consumer_key,
                         client_secret=self.consumer_secret,
                         grant_type='authorization_code',
                         code=code))

        response = requests.post(self.authorize_url, data=data)

        if not response.ok:
            response.raise_for_status()

        return _parse_response(response)

    def request(self, http_method, url, access_token=None, **params):
        '''Sends a request to an OAuth 2.0 endpoint, properly wrapped around
        requests.'''
        if access_token is None and self.access_token is None:
            raise ValueError('Access token must be set!')
        elif access_token is not None:
            self.access_token = access_token

        params.update({'access_token': self.access_token})

        response = requests.request(http_method, url, params=params)

        if not response.ok:
            response.raise_for_status()

        return _parse_response(response)


class OAuth1Service(object):
    '''An OAuth 1.0/a Service container.

    This class provides a container for an OAuth Service provider. It utilizes
    the OAuthHook module which in turn is hooked into Python Requests.
    Primarily this object can be used to provide a clean interface to provider
    endpoints and helps streamline the process of making OAuth requests.

    You might intialize :class:`OAuthService` something like this::

        service = OAuth1Service(
                   'example',
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
    '''
    def __init__(self, name, consumer_key, consumer_secret, request_token_url,
            access_token_url, authorize_url, header_auth=False):
        self.name = name

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url

        # set to True to use header authentication for this service
        self.header_auth = header_auth

    def _construct_session(self, **kwargs):
        '''Construct the request session, supplying the consumer key and
        secret.'''
        hook = OAuth1Hook(consumer_key=self.consumer_key,
                          consumer_secret=self.consumer_secret,
                          **kwargs)
        return requests.session(hooks={'pre_request': hook})

    def get_request_token(self, http_method, **data):
        '''Gets a request token from the request token endpoint.'''
        auth_session = \
                self._construct_session(header_auth=self.header_auth)

        response = auth_session.request(http_method,
                                        self.request_token_url,
                                        data=data)

        if not response.ok:
            response.raise_for_status()

        data = dict(parse_qsl(response.content))
        return data['oauth_token'], data['oauth_token_secret']

    def get_authorize_url(self, request_token, **params):
        '''Returns a proper authorize URL.'''
        params.update({'oauth_token': quote(request_token)})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self, request_token, request_token_secret,
                         http_method, **params):
        '''Retrieves the access token.'''
        auth_session = self._construct_session(
                                access_token=request_token,
                                access_token_secret=request_token_secret,
                                header_auth=self.header_auth)

        response = auth_session.request(http_method,
                                        self.access_token_url,
                                        params=params)

        if not response.ok:
            response.raise_for_status()

        return _parse_response(response)

    def get_authenticated_session(self, access_token, access_token_secret,
            header_auth=False):
        '''Returns an authenticated Requests session utilizing the hook.'''
        return self._construct_session(access_token=access_token,
                                       access_token_secret=access_token_secret,
                                       header_auth=header_auth)
