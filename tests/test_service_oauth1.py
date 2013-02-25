# -*- coding: utf-8 -*-
'''
    rauth.test_service_oauth1
    -------------------------

    Test suite for rauth.service.OAuth1Service.
'''

from base import RauthTestCase, parameterize
from test_service import HttpMixin, input_product_gen

from rauth.service import OAuth1Service, Service
from rauth.session import OAUTH1_DEFAULT_TIMEOUT, OAuth1Session
from rauth.utils import FORM_URLENCODED

from hashlib import sha1
from urllib import quote
from urlparse import parse_qsl

from mock import patch

import rauth

import requests


class OAuth1ServiceTestCase(RauthTestCase, HttpMixin):
    def setUp(self):
        RauthTestCase.setUp(self)

        request_token_url = 'http://example.com/request'
        access_token_url = 'http://example.com/access'
        authorize_url = 'http://example.com/authorize'
        base_url = 'http://example.com/api/'

        self.service = OAuth1Service('000',
                                     '111',
                                     name='service',
                                     request_token_url=request_token_url,
                                     access_token_url=access_token_url,
                                     authorize_url=authorize_url,
                                     base_url=base_url)

        self.service.request = self.fake_request
        self.service.access_token = '123'
        self.service.access_token_secret = '456'

    def fake_get_auth_header(self, oauth_params, realm=None):
        auth_header = 'OAuth realm="{realm}"'.format(realm=realm)
        params = ''
        for k, v in oauth_params.iteritems():
            params += ',{key}="{value}"'.format(key=k, value=quote(str(v)))
        auth_header += params
        return auth_header

    @patch.object(rauth.session.HmacSha1Signature, 'sign')
    @patch.object(rauth.session, 'time')
    @patch.object(rauth.session, 'random')
    @patch.object(requests.Session, 'request')
    def fake_request(self,
                     method,
                     url,
                     mock_request,
                     mock_random,
                     mock_time,
                     mock_sig,
                     access_token=None,
                     access_token_secret=None,
                     header_auth=False,
                     realm='',
                     **kwargs):
        fake_random = 1
        fake_time = 1
        fake_sig = 'foo'
        fake_sig_meth = 'HMAC-SHA1'
        fake_nonce = sha1(str(fake_random)).hexdigest()

        mock_request.return_value = self.response
        mock_random.return_value = fake_random
        mock_time.return_value = fake_time
        mock_sig.return_value = fake_sig

        method = method
        url = self.service._set_url(url)

        access_token, access_token_secret = \
            self.service._parse_access_tokens(access_token,
                                              access_token_secret)

        service = Service('service',
                          self.service.base_url,
                          self.service.authorize_url)
        session = self.service.get_session((access_token, access_token_secret))

        r = service.request(session,
                            method,
                            url,
                            header_auth=header_auth,
                            realm=realm,
                            **kwargs)

        if isinstance(kwargs.get('params'), basestring):
            kwargs['params'] = dict(parse_qsl(kwargs['params']))

        if isinstance(kwargs.get('data'), basestring):
            kwargs['data'] = dict(parse_qsl(kwargs['data']))

        kwargs.setdefault('headers', {})

        if not 'x-rauth-root-url' in kwargs['headers']:
            kwargs['headers'].update({'x-rauth-root-url': url})

        if not 'x-rauth-params-data' in kwargs['headers']:
            p, d = kwargs.get('params', {}), kwargs.get('data', {})
            kwargs['headers'].update({'x-rauth-params-data': (p, d)})

        oauth_params = {'oauth_consumer_key': session.consumer_key,
                        'oauth_nonce': fake_nonce,
                        'oauth_signature_method': fake_sig_meth,
                        'oauth_timestamp': fake_time,
                        'oauth_token': access_token,
                        'oauth_version': session.VERSION,
                        'oauth_signature': fake_sig}

        if header_auth:
            headers = {'Authorization':
                       self.fake_get_auth_header(oauth_params, realm=realm)}

            kwargs['headers'].update(headers)
        elif method.upper() in ('POST', 'PUT'):
            kwargs.setdefault('data', {})

            kwargs['data'].update(**oauth_params)
            kwargs.setdefault('headers', {})

            kwargs['headers'].update({'Content-Type': FORM_URLENCODED})
        else:
            kwargs.setdefault('params', {})
            kwargs['params'].update(**oauth_params)

        mock_request.assert_called_with(method,
                                        url,
                                        timeout=OAUTH1_DEFAULT_TIMEOUT,
                                        **kwargs)
        return r

    def test_get_session(self):
        s = self.service.get_session()
        self.assertIsInstance(s, OAuth1Session)

    def test_get_session_with_token(self):
        token = ('foo', 'bar')
        s1 = self.service.get_session(token)
        s2 = self.service.get_session(token)

        # ensure we are getting back the same object
        self.assertIs(s1, s2)

    def test_get_raw_request_token(self):
        resp = 'oauth_token=foo&oauth_token_secret=bar'
        self.response.content = resp
        r = self.service.get_raw_request_token()
        self.assertEqual(r.content, resp)

    def test_get_raw_request_token_missing_request_token_url(self):
        self.service.request_token_url = None
        resp = 'oauth_token=foo&oauth_token_secret=bar'
        self.response.content = resp
        with self.assertRaises(TypeError) as e:
            self.service.get_raw_request_token()
        self.assertEqual(str(e.exception),
                         'request_token_url must not be None')

    def test_get_request_token(self):
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        request_token, request_token_secret = self.service.get_request_token()
        self.assertEqual(request_token, 'foo')
        self.assertEqual(request_token_secret, 'bar')

    def test_get_authorize_url(self):
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        request_token, request_token_secret = self.service.get_request_token()

        url = self.service.get_authorize_url(request_token)
        expected_fmt = 'http://example.com/authorize?oauth_token={0}'
        self.assertEqual(url, expected_fmt.format(request_token))

    def test_get_raw_access_token(self):
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        request_token, request_token_secret = self.service.get_request_token()

        resp = 'oauth_token=foo&oauth_token_secret=bar'
        self.response.content = resp
        r = self.service.get_raw_access_token(request_token,
                                              request_token_secret)
        self.assertEqual(r.content, resp)

    def test_get_raw_access_token_missing_access_token_url(self):
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        request_token, request_token_secret = self.service.get_request_token()

        self.service.access_token_url = None
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'

        with self.assertRaises(TypeError) as e:
            self.service.get_raw_access_token(request_token,
                                              request_token_secret)
        self.assertEqual(str(e.exception),
                         'access_token_url must not be None')

    def test_get_access_token(self):
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        request_token, request_token_secret = self.service.get_request_token()

        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        access_token, access_token_secret = \
            self.service.get_access_token(request_token,
                                          request_token_secret)
        self.assertEqual(access_token, 'foo')
        self.assertEqual(access_token_secret, 'bar')

    def test_request_malformed(self):
        self.service.access_token_secret = None

        with self.assertRaises(TypeError) as e:
            self.service.request('GET',
                                 'baz',
                                 access_token='foo')

        self.assertEqual(str(e.exception),
                         'Either both or neither access_token and '
                         'access_token_secret must be supplied')

    def test_request_with_optional_params_oauth_callback(self):
        params = {'oauth_callback': 'http://example.com/callback'}
        r = self.service.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_params_oauth_verifier(self):
        params = {'oauth_verifier': 'foo'}
        r = self.service.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_params_oauth_version(self):
        params = {'oauth_verifier': 'foo'}
        r = self.service.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_params_as_string(self):
        params = 'oauth_callback=http://example.com/callback'
        r = self.service.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_data_as_string(self):
        data = 'oauth_callback=http://example.com/callback'
        r = self.service.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)

    def test_request_with_optional_params_with_data(self):
        data = {'oauth_callback': 'http://example.com/callback'}
        r = self.service.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)

    def test_request_with_header_auth(self):
        r = self.service.request('GET',
                                 'http://example.com/',
                                 header_auth=True)
        self.assert_ok(r)

    def test_request_with_header_auth_with_realm(self):
        r = self.service.request('GET',
                                 'http://example.com/',
                                 header_auth=True,
                                 realm='http://example.com/foo/')
        self.assert_ok(r)

    @parameterize(input_product_gen())
    def test_request(self, method, kwargs):
        r = self.service.request(method, 'foo', **kwargs)
        self.assert_ok(r)
