# -*- coding: utf-8 -*-
'''
    rauth.request
    -------------

    Provides a wrapper around the requests.Request object for OAuth and Ofly
    parameter injection.
'''

import time
import random

from hashlib import sha1
from urllib import quote, urlencode
from urlparse import parse_qsl

from requests import Request, Session

from rauth.oauth import HmacSha1Signature


OAUTH1_DEFAULT_TIMEOUT = OAUTH2_DEFAULT_TIMEOUT = OFLY_DEFAULT_TIMEOUT = 300.0


class RauthRequest(Request):
    def __init__(self, **kwargs):
        # Session params
        self.session_kwargs = {}
        self.session_kwargs['stream'] = kwargs.pop('stream', None)
        self.session_kwargs['timeout'] = kwargs.pop('timeout', None)
        self.session_kwargs['verify'] = kwargs.pop('verify', None)
        self.session_kwargs['cert'] = kwargs.pop('cert', None)
        self.session_kwargs['proxies'] = kwargs.pop('proxies', None)
        self.session_kwargs['allow_redirects'] = kwargs.pop('allow_redirects',
                                                            False)
        # initialize a `requests.Session` object
        self.session = kwargs.pop('session', None) or Session()

        # use any preexisting prepared request
        self.prepared = kwargs.get('_prepared', None)

        super(RauthRequest, self).__init__(**kwargs)

    def __repr__(self):
        return r'<{0} [{1}]>'.format(self.__class__.__name__, self.method)

    def _generate_request(self):
        raise NotImplementedError

    def send(self):
        '''Calls :meth:`prepare` sending the result via a request.Session
        instance.'''
        self._generate_request()
        return self.session.send(self.prepared or self.prepare(),
                                **self.session_kwargs)


class OAuth1Request(RauthRequest):
    def __init__(self, consumer_key=None, consumer_secret=None, **kwargs):
        # consumer credentials
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # access token credentials
        self.access_token = kwargs.pop('access_token', None)
        self.access_token_secret = kwargs.pop('access_token_secret', None)

        # a truthy value will default to using header-based auth
        self.header_auth = kwargs.pop('header_auth', False)

        # sets the signature method to be used
        self.signature = kwargs.pop('signature', HmacSha1Signature())

        # OAuth params
        self.oauth_callback = kwargs.pop('oauth_callback', None)
        self.oauth_verifier = kwargs.pop('oauth_verifier', None)
        self.oauth_version = kwargs.pop('oauth_version', '1.0')

        kwargs.setdefault('allow_redirects', False)
        kwargs.setdefault('timeout', OAUTH1_DEFAULT_TIMEOUT)

        super(OAuth1Request, self).__init__(**kwargs)

        self.params_and_data = {}

        self.__dict__.update(**kwargs)

    def _generate_request(self):
        # set the Content-Type if unspecified
        if self.method in ('POST', 'PUT'):
            self.__dict__['headers'].setdefault('Content-Type',
                                         'application/x-www-form-urlencoded')

        # parse optional oauth parameters
        for param in ('oauth_callback', 'oauth_verifier'):
            self._parse_optional_param(param)

        # populate and sign the necessary OAuth params
        self._update_params_and_data()

        if self.header_auth:
            self.headers['Authorization'] = self.auth_header
        elif self.method in ('POST', 'PUT'):
            self.data.update(**self.__dict__.pop('params_and_data'))
        else:
            self.params.update(**self.__dict__.pop('params_and_data'))

    def _parse_optional_param(self, oauth_param):
        '''Parses and sets optional OAuth parameters on a request.

        :param oauth_param: The OAuth parameter to parse.
        :param request: The Request object.
        '''
        params_is_string = type(self.params) == str
        data_is_string = type(self.data) == str
        params = self.params
        data = self.data

        # special handling if we're handed a string
        if params_is_string:
            params = dict(parse_qsl(self.params))

        # remove any oauth parameters and set them as attributes
        if oauth_param in params:
            setattr(self, oauth_param, params.pop(oauth_param))
        if not data_is_string and oauth_param in data:
            setattr(self, oauth_param, data.pop(oauth_param))

        # re-encode the params if they were a string, without any oauth
        if params_is_string:
            self.params = urlencode(params)

    def _update_params_and_data(self):
        params = {}

        params['oauth_consumer_key'] = self.consumer_key
        params['oauth_nonce'] = sha1(str(random.random())).hexdigest()
        params['oauth_timestamp'] = int(time.time())
        params['oauth_version'] = self.oauth_version

        if self.oauth_callback is not None:
            params['oauth_callback'] = self.oauth_callback

        if self.access_token is not None:
            params['oauth_token'] = self.access_token

        if self.oauth_verifier is not None:
            params['oauth_verifier'] = self.oauth_verifier

        params['oauth_signature_method'] = self.signature.NAME

        self.params_and_data.update(**params)

        self.params_and_data['oauth_signature'] = \
                self.signature.sign(self,
                                    self.consumer_secret,
                                    self.access_token_secret)

    @property
    def auth_header(self):
        auth_header = 'OAuth realm="{0}"'.format(self.realm)
        params = ''
        for k, v in self.oauth_params.items():
            params += ',{0}="{1}"'.format(k, quote(str(v)))
        auth_header += params
        return auth_header
