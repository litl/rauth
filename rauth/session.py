# -*- coding: utf-8 -*-
'''
    rauth.session
    -------------

    Specially wrapped `request.Session` objects.
'''

from datetime import datetime
from hashlib import sha1, md5
from random import random
from time import time
from urllib import quote, urlencode
from urlparse import parse_qsl, urlsplit

from rauth.oauth import HmacSha1Signature
from rauth.utils import FORM_URLENCODED

from requests.sessions import Session

OAUTH1_DEFAULT_TIMEOUT = OAUTH2_DEFAULT_TIMEOUT = OFLY_DEFAULT_TIMEOUT = 300.0


class OAuth1Session(Session):
    VERSION = '1.0'

    def __init__(self,
                 consumer_key,
                 consumer_secret,
                 access_token=None,
                 access_token_secret=None,
                 signature=None,
                 service=None):

        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        self.access_token = access_token
        self.access_token_secret = access_token_secret

        if signature is None:
            self.signature = HmacSha1Signature()

        self.service = service

        super(OAuth1Session, self).__init__()

    def request(self,
                method,
                url,
                header_auth=False,
                realm=None,
                **req_kwargs):

        req_kwargs.setdefault('timeout', OAUTH1_DEFAULT_TIMEOUT)

        self.oauth_params = {}

        # set the OAuth params on the oauth_params attribute
        self._set_oauth_params()

        # parse optional OAuth parameters
        for param in ('oauth_callback', 'oauth_verifier', 'oauth_version'):
            self._parse_optional_params(param, req_kwargs)

        # sign the request
        self.oauth_params['oauth_signature'] = self.signature.sign(self,
                                                                   method,
                                                                   url,
                                                                   req_kwargs)

        if header_auth:
            req_kwargs.setdefault('headers', {})
            req_kwargs['headers'].update({'Authorization':
                                           self._get_auth_header()})
        elif method.upper() in ('POST', 'PUT'):
            req_kwargs.setdefault('headers', {})
            req_kwargs['headers'].setdefault('Content-Type', FORM_URLENCODED)
            req_kwargs.setdefault('data', {})
            req_kwargs['data'].update(self.__dict__.pop('oauth_params'))
        else:
            req_kwargs.setdefault('params', {})
            req_kwargs['params'].update(self.__dict__.pop('oauth_params'))

        return super(OAuth1Session, self).request(method, url, **req_kwargs)

    def _parse_optional_params(self, oauth_param, req_kwargs):
        '''Parses and sets optional OAuth parameters on a request.

        :param oauth_param: The OAuth parameter to parse.
        :param req_kwargs: The keyworded arguments passed to the request
            method.
        '''
        params_is_string = type(req_kwargs.get('params')) == str
        data_is_string = type(req_kwargs.get('data')) == str

        params = req_kwargs.get('params', {})
        data = req_kwargs.get('data', {})

        # special handling if we're handed a string
        if params_is_string and params:
            params = dict(parse_qsl(params))

        # remove any oauth parameters and set them as attributes
        if oauth_param in params:
            self.oauth_params[oauth_param] = params.pop(oauth_param)
        if not data_is_string and oauth_param in data:
            self.oauth_params[oauth_param] = data.pop(oauth_param)

        # re-encode the params if they were a string, without any oauth
        if params_is_string:
            req_kwargs['params'] = urlencode(params)

    def _set_oauth_params(self):
        '''Prepares OAuth params for signing.'''
        self.oauth_params['oauth_consumer_key'] = self.consumer_key
        self.oauth_params['oauth_nonce'] = sha1(str(random())).hexdigest()
        self.oauth_params['oauth_signature_method'] = self.signature.NAME
        self.oauth_params['oauth_timestamp'] = int(time())

        if self.access_token is not None:
            self.oauth_params['oauth_token'] = self.access_token

        self.oauth_params['oauth_version'] = self.VERSION

    def _get_auth_header(self, realm=None):
        oauth_params = self.__dict__.pop('oauth_params')
        auth_header = 'OAuth realm="{realm}"'.format(realm=realm)
        params = ''
        for k, v in oauth_params.items():
            params += ',{key}="{value}"'.format(key=k, value=quote(str(v)))
        auth_header += params
        return auth_header


class OAuth2Session(Session):
    def __init__(self,
                 client_id,
                 client_secret,
                 access_token=None,
                 service=None):
        self.client_id = client_id
        self.client_secret = client_secret

        self.access_token = access_token

        self.service = service

        super(OAuth2Session, self).__init__()

    def request(self, method, url, **req_kwargs):
        req_kwargs.setdefault('params', {}).update({'access_token':
                                                    self.access_token})
        req_kwargs.setdefault('timeout', OAUTH2_DEFAULT_TIMEOUT)

        return super(OAuth2Session, self).request(method, url, **req_kwargs)


class OflySession(Session):
    def __init__(self,
                 app_id,
                 app_secret,
                 service=None):
        self.app_id = app_id
        self.app_secret = app_secret

        self.service = service

        super(OflySession, self).__init__()

    def request(self, method, url, header_auth=False, **req_kwargs):
        req_kwargs.setdefault('params', {})
        req_kwargs.setdefault('headers', {})
        req_kwargs.setdefault('timeout', OFLY_DEFAULT_TIMEOUT)

        params, headers = OflySession.sign(url,
                                           self.app_id,
                                           self.app_secret,
                                           req_kwargs['params'])

        req_kwargs['params'].update(params)

        if header_auth:
            req_kwargs['headers'].update(headers)

        return super(OflySession, self).request(method, url, **req_kwargs)

    @staticmethod
    def sign(url, app_id, app_secret, hash_meth='sha1', **params):
        if hash_meth == 'sha1':
            hash_meth = sha1
        elif hash_meth == 'md5':
            hash_meth = md5
        else:
            raise TypeError('hash_meth must be one of "sha1", "md5"')

        def param_sorting(params):
            def sorting_gen():
                for k in sorted(params.keys()):
                    yield '='.join((k, params[k]))
            return '&'.join(sorting_gen())

        now = datetime.utcnow()
        milliseconds = now.microsecond / 1000

        time_format = '%Y-%m-%dT%H:%M:%S.{0}Z'.format(milliseconds)
        ofly_params = {'oflyAppId': app_id,
                       'oflyHashMeth': hash_meth.upper(),
                       'oflyTimestamp': now.strftime(time_format)}

        url_path = urlsplit(url).path

        signature_base_string = app_secret + url_path + '?'

        # only append params if there are any, to avoid a leading ampersand
        sorted_params = param_sorting(params)
        if len(sorted_params):
            signature_base_string += sorted_params + '&'

        signature_base_string += param_sorting(ofly_params)

        params['oflyApiSig'] = hash_meth(signature_base_string).hexdigest()

        # return the raw ofly_params for use in the header
        return param_sorting(params), ofly_params
