# -*- coding: utf-8 -*-
'''
    rauth.test_session
    ------------------

    Test suite for rauth.session.
'''

from base import RauthTestCase
from rauth.session import OAuth1Session, OAuth2Session, OflySession


import requests

import json

import sys
if sys.version_info >= (3, 3):
    from unittest.mock import patch
else:
    from mock import patch


class RequestMixin(object):
    def assert_ok(self, r):
        self.assertEqual(json.loads(r.content), {'status': 'ok'})

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request, **kwargs):
        mock_request.return_value = self.response
        self.assert_ok(self.session.request('GET',
                                            'http://example.com/',
                                            **kwargs))


class OAuth1SessionTestCase(RauthTestCase, RequestMixin):
    def setUp(self):
        RauthTestCase.setUp(self)

        self.session = OAuth1Session('123', '345')

    @patch.object(requests.Session, 'request')
    def test_request_with_optional_params(self, mock_request):
        mock_request.return_value = self.response
        params = {'oauth_callback': 'http://example.com/callback'}
        r = self.session.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_optional_params_as_string(self, mock_request):
        mock_request.return_value = self.response
        params = 'oauth_callback=http://example.com/callback'
        r = self.session.request('GET', 'http://example.com/', params=params)
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_optional_data_as_string(self, mock_request):
        mock_request.return_value = self.response
        data = 'oauth_callback=http://example.com/callback'
        r = self.session.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_optional_params_with_data(self, mock_request):
        mock_request.return_value = self.response
        data = {'oauth_callback': 'http://example.com/callback'}
        r = self.session.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_header_auth(self, mock_request):
        mock_request.return_value = self.response
        r = self.session.request('GET',
                                 'http://example.com/',
                                 header_auth=True)
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_not_alphanumeric_data_as_string(self, mock_request):
        mock_request.return_value = self.response
        data = 'foo=こんにちは世界'
        r = self.session.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_not_alphanumeric_data_as_dict(self, mock_request):
        mock_request.return_value = self.response
        data = {'foo': 'こんにちは世界'}
        r = self.session.request('POST', 'http://example.com/', data=data)
        self.assert_ok(r)


class OAuth2SessionTestCase(RauthTestCase, RequestMixin):
    def setUp(self):
        RauthTestCase.setUp(self)

        self.session = OAuth2Session('123', '345')
        self.session_no_creds = OAuth2Session()

    def test_with_credentials(self):
        assert self.session.client_id == '123'
        assert self.session.client_secret == '345'

    def test_without_credentials(self):
        assert self.session_no_creds.client_id is None
        assert self.session_no_creds.client_secret is None


class OflySessionTestCase(RauthTestCase, RequestMixin):
    def setUp(self):
        RauthTestCase.setUp(self)

        self.session = OflySession('123', '345')

    def test_request(self):
        return super(OflySessionTestCase, self).test_request(user_id='123')

    @patch.object(requests.Session, 'request')
    def test_request_with_header_auth(self, mock_request):
        mock_request.return_value = self.response
        r = self.session.request('GET',
                                 'http://example.com/',
                                 user_id='123',
                                 header_auth=True)
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_md5(self, mock_request):
        mock_request.return_value = self.response
        r = self.session.request('GET',
                                 'http://example.com/',
                                 user_id='123',
                                 hash_meth='md5')
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_bad_hash_meth(self, mock_request):
        mock_request.return_value = self.response
        with self.assertRaises(TypeError) as e:
            self.session.request('GET',
                                 'http://example.com/',
                                 user_id='123',
                                 hash_meth='foo')
        self.assertEqual(str(e.exception),
                         'hash_meth must be one of "sha1", "md5"')
