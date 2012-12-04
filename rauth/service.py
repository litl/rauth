# -*- coding: utf-8 -*-
'''
    rauth.service
    -------------

    Provides OAuth 1.0/a, 2.0 and Ofly service containers.
'''

import hashlib
import json
import requests

from rauth.hook import OAuth1Hook
from rauth.utils import absolute_url, parse_utf8_qsl

from datetime import datetime
from urllib import quote, urlencode
from urlparse import urlsplit

DEFAULT_TIMEOUT = 300


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


class Response(object):
    '''A service response container.

    :param content: The parsed response.content else unparsed.
    :param response: The unaltered response object from Requests.
    '''
    def __init__(self, response):
        self.response = response

    @property
    def content(self):
        # NOTE: it would be nice to use content-type here however we can't
        # trust services to be honest with this header so for now the
        # following is more robust and less prone to fragility when the header
        # isn't set properly
        if isinstance(self.response.content, basestring):
            try:
                content = json.loads(self.response.content)
            except ValueError:
                content = parse_utf8_qsl(self.response.content)
        else:
            content = self.response.content
        return content


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
                              consumer_key='123',
                              consumer_secret='456',
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

    :param consumer_key: Client consumer key.
    :param consumer_secret: Client consumer secret.
    :param name: The service name, defaults to None.
    :param authorize_url: Authorize endpoint, defaults to None.
    '''
    TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S.{0}Z'
    MICRO_MILLISECONDS_DELTA = 1000

    def __init__(self, consumer_key, consumer_secret, name=None,
                 authorize_url=None, base_url=None):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # wrap requests in a Requests session
        self.session = requests.session()

        super(OflyService, self).__init__(name,
                                          base_url,
                                          authorize_url)

    def _micro_to_milliseconds(self, microseconds):
        return microseconds / self.MICRO_MILLISECONDS_DELTA

    def _sort_params(self, params):
        def sorting():
            for k in sorted(params.keys()):
                yield '='.join((k, params[k]))
        return '&'.join(sorting())

    def _sha1_sign_params(self, url, header_auth=False, **params):
        now = datetime.utcnow()
        milliseconds = self._micro_to_milliseconds(now.microsecond)
        time_format = self.TIMESTAMP_FORMAT.format(milliseconds)
        ofly_params = {'oflyAppId': self.consumer_key,
                       'oflyHashMeth': 'SHA1',
                       'oflyTimestamp': now.strftime(time_format)}

        # select only the path for signing
        url_path = urlsplit(url).path

        signature_base_string = \
            self.consumer_secret \
            + url_path \
            + '?'

        # only append params if there are any, to avoid a leading ampersand
        sorted_params = self._sort_params(params)
        if len(sorted_params) > 0:
            signature_base_string += sorted_params + '&'

        signature_base_string += self._sort_params(ofly_params)

        params['oflyApiSig'] = hashlib.sha1(signature_base_string).hexdigest()

        if not header_auth:
            # don't use header authentication
            params = dict(params.items() + ofly_params.items())
            return self._sort_params(params)

        # return the raw ofly_params for use in the header
        return self._sort_params(params), ofly_params

    def get_authorize_url(self, remote_user=None, redirect_uri=None, **params):
        '''Returns a proper authorize URL.

        :param remote_user: This is the oflyRemoteUser param. Defaults to None.
        :param redirect_uri: This is the oflyCallbackUrl. Defaults to None.
        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        '''
        if remote_user is not None:
            params.update({'oflyRemoteUser': remote_user})

        if redirect_uri is not None:
            params.update({'oflyCallbackUrl': redirect_uri})

        params = '?' + self._sha1_sign_params(self.authorize_url, **params)
        return self.authorize_url + params

    def request(self, method, uri, **kwargs):
        '''Sends a request to an Ofly endpoint, properly wrapped around
        requests.

        :param method: A string representation of the HTTP method to be
            used.
        :param url: The resource to be requested.
        :param header_auth: Authenication via header, defaults to False.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        params = kwargs.pop('params', None)
        data = kwargs.pop('data', None)

        if params is None:
            params = {}

        kwargs.setdefault('timeout', DEFAULT_TIMEOUT)

        if self.base_url is not None and not absolute_url(uri):
            uri = self.base_url + uri

        header_auth = kwargs.pop('header_auth', False)
        if header_auth:
            params, headers = self._sha1_sign_params(uri,
                                                     header_auth,
                                                     **params)

            response = self.session.request(method,
                                            uri + '?' + params,
                                            headers=headers,
                                            **kwargs)
        else:
            params = self._sha1_sign_params(uri, **params)

            response = self.session.request(method,
                                            uri + '?' + params,
                                            data=data,
                                            **kwargs)

        return Response(response)


class OAuth2Service(Service):
    '''An OAuth 2.0 Service container.

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

    :param client_id: Client consumer key.
    :param client_secret: Client consumer secret.
    :param name: The service name, defaults to None.
    :param access_token_url: Access token endpoint, defaults to None.
    :param authorize_url: Authorize endpoint, defaults to None.
    :param access_token: An access token, defaults to None.
    '''
    def __init__(self, client_id=None, client_secret=None, name=None,
                 access_token_url=None, authorize_url=None, access_token=None,
                 base_url=None, **kwargs):
        self.client_id = client_id or kwargs.get('consumer_key')
        self.client_secret = client_secret or kwargs.get('consumer_secret')

        # DEPRECATED: these are superceded by client_id and client_secret
        self.consumer_key = kwargs.get('consumer_key', client_id)
        self.consumer_secret = kwargs.get('consumer_secret', client_secret)

        if None in (self.consumer_key, self.consumer_secret):
            raise TypeError('client_id and client_secret must not be None')

        self.access_token_url = access_token_url

        self.access_token = None
        if access_token is not None:
            self.access_token = access_token

        self.session = requests.session()

        super(OAuth2Service, self).__init__(name,
                                            base_url,
                                            authorize_url,
                                            access_token=access_token)

    def get_authorize_url(self, response_type='code', **params):
        '''Returns a proper authorize URL.

        :param reponse_type: The response type. Defaults to 'code'.
        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        '''
        params.update({'client_id': self.consumer_key,
                       'response_type': response_type})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self, method='POST', **kwargs):
        '''Retrieves the access token.

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
            kwargs['auth'] = (self.consumer_key, self.consumer_secret)
        else:
            kwargs[key].update(client_id=self.consumer_key,
                               client_secret=self.consumer_secret,
                               grant_type=grant_type)

        response = self.session.request(method,
                                        self.access_token_url,
                                        **kwargs)

        return Response(response)

    def request(self, method, uri, access_token=None, **kwargs):
        '''Sends a request to an OAuth 2.0 endpoint, properly wrapped around
        requests.

        :param method: A string representation of the HTTP method to be used.
        :param uri: The resource to be requested.
        :param access_token: Overrides self.access_token. Defaults to None.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''

        # see if we can prepend base_url
        if self.base_url is not None and not absolute_url(uri):
            uri = self.base_url + uri

        # see if we can use a stored access_token
        if access_token is None and self.access_token is None:
            raise TypeError('access_token must not be None')

        if access_token is None:
            access_token = self.access_token

        kwargs.setdefault('params', {}).update(access_token=access_token)
        kwargs.setdefault('timeout', DEFAULT_TIMEOUT)

        response = self.session.request(method, uri, **kwargs)

        return Response(response)


class OAuth1Service(Service):
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

    :param name: The service name, defaults to None.
    :param consumer_key: Client consumer key, required for signing.
    :param consumer_secret: Client consumer secret, required for signing.
    :param request_token_url: Request token endpoint, defaults to None.
    :param access_token_url: Access token endpoint, defaults to None.
    :param authorize_url: Authorize endpoint, defaults to None.
    :param header_auth: Authenication via header, defaults to False.
    :param signature: The signature(object) strategy to be used. Currently
                        supported PlaintextSignature and HmacSha1Signature
    '''
    def __init__(self, consumer_key, consumer_secret, name=None,
                 request_token_url=None, access_token_url=None,
                 authorize_url=None, header_auth=False, base_url=None,
                 access_token=None, access_token_secret=None, signature=None):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # authorization endpoints
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url

        # set to True to use header authentication for this service
        self.header_auth = header_auth

        self.signature = signature

        params = dict(access_token=access_token,
                      access_token_secret=access_token_secret)

        super(OAuth1Service, self).__init__(name,
                                            base_url,
                                            authorize_url,
                                            **params)

    def _construct_session(self, **kwargs):
        '''Construct the request session, supplying the consumer key and
        secret.

        :param \*\*kwargs: Extra keyworded arguments to be passed to the
            OAuth1Hook constructor.
        '''
        hook = OAuth1Hook(consumer_key=self.consumer_key,
                          consumer_secret=self.consumer_secret,
                          signature=self.signature,
                          **kwargs)
        return requests.session(hooks={'pre_request': hook})

    def get_raw_request_token(self, method='GET', oauth_callback='oob',
                              **kwargs):
        '''Gets a response from the request token endpoint.

        Returns the entire parsed response, without trying to pull out the
        token and secret.  Use this if your endpoint doesn't use the usual
        names for 'oauth_token' and 'oauth_token_secret'.

        :param method: A string representation of the HTTP method to be used.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        # ensure we've set the request_token_url
        if self.request_token_url is None:
            raise TypeError('request_token_url must not be None')

        auth_session = \
            self._construct_session(header_auth=self.header_auth,
                                    default_oauth_callback=oauth_callback)

        response = auth_session.request(method,
                                        self.request_token_url,
                                        **kwargs)

        # TODO: use the following instead
        #if not response.ok:
        #    return response.content

        response.raise_for_status()

        return parse_utf8_qsl(response.content)

    def get_request_token(self, method='GET', **kwargs):
        '''Gets a request token from the request token endpoint.

        :param method: A string representation of the HTTP method to be used.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        data = self.get_raw_request_token(method=method, **kwargs)
        return data['oauth_token'], data['oauth_token_secret']

    def get_authorize_url(self, request_token, **params):
        '''Returns a proper authorize URL.

        :param request_token: The request token as returned by
            :class:`get_request_token`.
        :param \*\*params: Additional keyworded arguments to be added to the
            request querystring.
        '''
        params.update({'oauth_token': quote(request_token)})
        params = '?' + urlencode(params)
        return self.authorize_url + params

    def get_access_token(self, method='GET', **kwargs):
        '''Retrieves the access token.

        :param method: A string representation of the HTTP method to be
            used.
        :param request_token: The request token as returned by
            :class:`get_request_token`.
        :param request_token_secret: The request token secret as returned by
            :class:`get_request_token`.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        # ensure we've set the access_token_url
        if self.access_token_url is None:
            raise TypeError('access_token_url must not be None')

        request_token = kwargs.pop('request_token')
        request_token_secret = kwargs.pop('request_token_secret')

        auth_session = \
            self._construct_session(access_token=request_token,
                                    access_token_secret=request_token_secret,
                                    header_auth=self.header_auth)

        response = auth_session.request(method,
                                        self.access_token_url,
                                        **kwargs)

        return Response(response)

    def get_authenticated_session(self, access_token, access_token_secret,
                                  header_auth=False):
        '''Returns an authenticated Requests session utilizing the hook.

        :param access_token: The access token as returned by
            :class:`get_access_token`
        :param access_token_secret: The access token secret as returned by
            :class:`get_access_token`
        :param header_auth: Authenication via header, defaults to False.
        '''
        return self._construct_session(access_token=access_token,
                                       access_token_secret=access_token_secret,
                                       header_auth=header_auth)

    def request(self, method, uri, access_token=None,
                access_token_secret=None, **kwargs):
        '''Makes a request using :class:`_construct_session`.

        :param method: A string representation of the HTTP method to be
            used.
        :param uri: The resource to be requested.
        :param access_token: The access token as returned by
            :class:`get_access_token`.
        :param access_token_secret: The access token secret as returned by
            :class:`get_access_token`.
        :param header_auth: Authenication via header, defaults to False.
        :param allow_redirects: Allows a request to redirect, defaults to True.
        :param \*\*kwargs: Optional arguments. Same as Requests.
        '''
        header_auth = kwargs.pop('header_auth', self.header_auth)

        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('headers', {})
        kwargs.setdefault('params', {})
        kwargs.setdefault('timeout', DEFAULT_TIMEOUT)

        # set the Content-Type if unspecified
        if method in ('POST', 'PUT'):
            kwargs['headers'].setdefault('Content-Type',
                                         'application/x-www-form-urlencoded')

        # prepend a base_url to the uri if we can
        if self.base_url is not None and not absolute_url(uri):
            uri = self.base_url + uri

        # check user supplied tokens
        tokens = (access_token, access_token_secret)
        all_tokens_none = all(v is None for v in tokens)
        if None in tokens and not all_tokens_none:
            raise TypeError('Either both or neither access_token and '
                            'access_token_secret must be supplied')

        # use default tokens if user supplied tokens are not present
        if all_tokens_none:
            access_token = self.access_token
            access_token_secret = self.access_token_secret

        session_params = dict(access_token=access_token,
                              access_token_secret=access_token_secret,
                              header_auth=header_auth)
        auth_session = self._construct_session(**session_params)

        response = auth_session.request(method,
                                        uri,
                                        **kwargs)

        return Response(response)
