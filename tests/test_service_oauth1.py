# -*- coding: utf-8 -*-
'''
    rauth.test_service_oauth1
    -------------------------

    Test suite for rauth.service.OAuth1Service.
'''

from base import RauthTestCase
from test_service import HttpMixin, RequestMixin, ServiceMixin

from rauth.compat import parse_qsl, quote, is_basestring, iteritems
from rauth.service import OAuth1Service
from rauth.session import OAUTH1_DEFAULT_TIMEOUT, OAuth1Session
from rauth.utils import CaseInsensitiveDict, ENTITY_METHODS, FORM_URLENCODED

from copy import deepcopy
from hashlib import sha1

from mock import patch

import rauth

import requests

import json
import pickle


class OAuth1ServiceTestCase(RauthTestCase, RequestMixin, ServiceMixin,
                            HttpMixin):
    consumer_key = '000'
    consumer_secret = '111'

    access_token = '123'
    access_token_secret = '456'

    def setUp(self):
        RauthTestCase.setUp(self)

        self.request_token_url = 'http://example.com/request'
        self.access_token_url = 'http://example.com/access'
        self.authorize_url = 'http://example.com/authorize'
        self.base_url = 'http://example.com/api/'

        self.service = OAuth1Service(self.consumer_key,
                                     self.consumer_secret,
                                     name='service',
                                     request_token_url=self.request_token_url,
                                     access_token_url=self.access_token_url,
                                     authorize_url=self.authorize_url,
                                     base_url=self.base_url)

        self.session = self.service.get_session(('123', '456'))

        # patches
        self.session.request = self.fake_request
        self.service.get_session = self.fake_get_session

    def fake_get_auth_header(self, oauth_params, realm=None):
        auth_header = 'OAuth realm="{realm}"'.format(realm=realm)
        params = ''
        for k, v in iteritems(oauth_params):
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
                     header_auth=False,
                     realm='',
                     **kwargs):
        fake_random = 1
        fake_time = 1
        fake_sig = 'foo'
        fake_sig_meth = 'HMAC-SHA1'
        fake_nonce = sha1(str(fake_random).encode('ascii')).hexdigest()

        mock_request.return_value = self.response
        mock_random.return_value = fake_random
        mock_time.return_value = fake_time
        mock_sig.return_value = fake_sig

        method = method
        url = self.session._set_url(url)

        service = OAuth1Service(self.consumer_key,
                                self.consumer_secret,
                                name='service',
                                request_token_url=self.request_token_url,
                                access_token_url=self.access_token_url,
                                authorize_url=self.authorize_url,
                                base_url=self.base_url)

        session = service.get_session((self.access_token,
                                       self.access_token_secret))

        r = session.request(method,
                            url,
                            header_auth=header_auth,
                            realm=realm,
                            **deepcopy(kwargs))

        kwargs.setdefault('headers', {})
        kwargs['headers'] = CaseInsensitiveDict(kwargs['headers'])

        entity_method = method.upper() in ENTITY_METHODS
        if entity_method:
            kwargs['headers'].setdefault('Content-Type', FORM_URLENCODED)

        form_urlencoded = \
            kwargs['headers'].get('Content-Type') == FORM_URLENCODED

        if is_basestring(kwargs.get('params')):
            kwargs['params'] = dict(parse_qsl(kwargs['params']))

        if is_basestring(kwargs.get('data')) and form_urlencoded:
            kwargs['data'] = dict(parse_qsl(kwargs['data']))

        oauth_params = {'oauth_consumer_key': session.consumer_key,
                        'oauth_nonce': fake_nonce,
                        'oauth_signature_method': fake_sig_meth,
                        'oauth_timestamp': fake_time,
                        'oauth_token': self.access_token,
                        'oauth_version': session.VERSION,
                        'oauth_signature': fake_sig}

        if header_auth:
            auth = mock_request.call_args[1]['auth']
            auth_header = self.fake_get_auth_header(oauth_params, realm=realm)
            self.assertEqual(auth(requests.Request()).headers['Authorization'],
                             auth_header)
            kwargs['auth'] = auth
        elif entity_method:
            kwargs['data'] = kwargs.get('data') or {}

            if form_urlencoded:
                kwargs['data'].update(oauth_params)
            else:
                kwargs.setdefault('params', {})
                kwargs['params'].update(oauth_params)
        else:
            kwargs.setdefault('params', {})
            kwargs['params'].update(**oauth_params)

        mock_request.assert_called_with(method,
                                        url,
                                        timeout=OAUTH1_DEFAULT_TIMEOUT,
                                        **kwargs)
        return r

    def fake_get_session(self, token=None, signature=None):
        return self.session

    def test_get_session(self):
        s = self.service.get_session()
        self.assertIsInstance(s, OAuth1Session)

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

    def test_get_request_token_with_json_decoder(self):
        self.response.content = json.dumps({'oauth_token': 'foo',
                                            'oauth_token_secret': 'bar'})
        request_token, request_token_secret = \
            self.service.get_request_token(decoder=json.loads)
        self.assertEqual(request_token, 'foo')
        self.assertEqual(request_token_secret, 'bar')

    def test_get_authorize_url(self):
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        request_token, request_token_secret = self.service.get_request_token()

        url = self.service.get_authorize_url(request_token)
        expected_fmt = 'http://example.com/authorize?oauth_token={0}'
        self.assertEqual(url, expected_fmt.format(request_token))

    def test_get_authorize_url_with_url_encoded_characters(self):
        token = 'uDV8XWNLSJjzMUSVfbG1gYHWMjY%3D'
        token_secret = 'e%2Bt9QCndiw1%2BtJbhy5UYVMAPTPo%3D'
        response_fmt = 'oauth_token={0}&oauth_token_secret={1}'
        self.response.content = response_fmt.format(token, token_secret)
        request_token, request_token_secret = self.service.get_request_token()

        url = self.service.get_authorize_url(request_token)
        expected_fmt = 'http://example.com/authorize?oauth_token={0}'
        self.assertEqual(url, expected_fmt.format(token))

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

    def test_get_access_token_with_json_decoder(self):
        self.response.content = 'oauth_token=foo&oauth_token_secret=bar'
        request_token, request_token_secret = self.service.get_request_token()

        self.response.content = json.dumps({'oauth_token': 'foo',
                                            'oauth_token_secret': 'bar'})
        access_token, access_token_secret = \
            self.service.get_access_token(request_token,
                                          request_token_secret,
                                          decoder=json.loads)
        self.assertEqual(access_token, 'foo')
        self.assertEqual(access_token_secret, 'bar')

    def test_request_with_optional_params_oauth_callback(self):
        params = {'oauth_callback': 'http://example.com/callback'}
        r = self.session.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_params_oauth_verifier(self):
        params = {'oauth_verifier': 'foo'}
        r = self.session.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_params_oauth_version(self):
        params = {'oauth_verifier': 'foo'}
        r = self.session.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_params_as_string(self):
        params = 'oauth_callback=http://example.com/callback'
        r = self.session.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    def test_request_with_optional_data_as_string(self):
        data = 'oauth_callback=http://example.com/callback'
        r = self.session.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)

    def test_request_with_optional_params_with_data(self):
        data = {'oauth_callback': 'http://example.com/callback'}
        r = self.session.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)

    def test_request_with_header_auth(self):
        r = self.session.request('GET',
                                 'http://example.com/',
                                 header_auth=True)
        self.assert_ok(r)

    def test_request_with_header_auth_with_realm(self):
        r = self.session.request('GET',
                                 'http://example.com/',
                                 header_auth=True,
                                 realm='http://example.com/foo/')
        self.assert_ok(r)

    def test_get_auth_session(self):
        resp = 'oauth_token=foo&oauth_token_secret=bar'
        self.response.content = resp
        s = self.service.get_auth_session('foo', 'bar')
        self.assertIsInstance(s, OAuth1Session)

    def test_get_auth_session_with_request_token_response(self):
        resp = 'oauth_token=foo&oauth_token_secret=bar'
        self.response.content = resp
        self.service.request_token_response = 'ok'
        s = self.service.get_auth_session('foo', 'bar')
        self.assertEqual(s.request_token_response, 'ok')

    def test_pickle_session(self):
        session = pickle.loads(pickle.dumps(self.session))

        # Add the fake request back to the session
        session.request = self.fake_request
        r = session.request('GET', 'http://example.com/', header_auth=True)
        self.assert_ok(r)
