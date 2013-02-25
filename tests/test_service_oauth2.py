# -*- coding: utf-8 -*-
'''
    rauth.test_service_oauth2
    -------------------------

    Test suite for rauth.service.OAuth2Service.
'''

from base import RauthTestCase, parameterize
from test_service import HttpMixin, input_product_gen

from rauth.service import OAuth2Service, Service
from rauth.session import OAUTH2_DEFAULT_TIMEOUT, OAuth2Session

from urlparse import parse_qsl

from mock import patch

import requests


class OAuth2ServiceTestCase(RauthTestCase, HttpMixin):
    def setUp(self):
        RauthTestCase.setUp(self)

        self.access_token_url = 'https://example.com/access'
        self.authorize_url = 'https://example.com/authorize'
        self.base_url = 'https://example/api/'

        self.service = OAuth2Service('000',
                                     '111',
                                     access_token_url=self.access_token_url,
                                     authorize_url=self.authorize_url,
                                     base_url=self.base_url)

        self.service.request = self.fake_request
        self.service.access_token = '123'

    @patch.object(requests.Session, 'request')
    def fake_request(self,
                     method,
                     url,
                     mock_request,
                     access_token=None,
                     **kwargs):
        mock_request.return_value = self.response

        access_token = access_token or self.service.access_token

        url = self.service._set_url(url)

        session = self.service.get_session(access_token)
        service = Service('service',
                          self.service.base_url,
                          self.service.authorize_url)
        r = service.request(session, method, url, **kwargs)

        if isinstance(kwargs.get('params', {}), basestring):
            kwargs['params'] = dict(parse_qsl(kwargs['params']))

        kwargs.setdefault('params', {})
        kwargs['params'].update(**{'access_token': access_token})

        mock_request.assert_called_with(method,
                                        url,
                                        timeout=OAUTH2_DEFAULT_TIMEOUT,
                                        **kwargs)
        return r

    def test_get_session(self):
        s = self.service.get_session()
        self.assertIsInstance(s, OAuth2Session)

    def test_get_session_with_token(self):
        s1 = self.service.get_session('foo')
        s2 = self.service.get_session('foo')

        # ensure we are getting back the same object
        self.assertIs(s1, s2)

    def test_get_authorize_url(self):
        url = self.service.get_authorize_url()
        expected_fmt = 'https://example.com/authorize?client_id={0}'
        self.assertEqual(url, expected_fmt.format(self.service.client_id))

    def test_get_raw_access_token(self):
        resp = 'access_token=123&expires_in=3600&refresh_token=456'
        self.response.content = resp
        r = self.service.get_raw_access_token()
        self.assertEqual(r.content, resp)

    def test_get_raw_access_token_with_params(self):
        resp = 'access_token=123&expires_in=3600&refresh_token=456'
        self.response.content = resp
        r = self.service.get_raw_access_token(params={'a': 'b'})
        self.assertEqual(r.content, resp)

    def test_get_access_token(self):
        self.response.content = \
            'access_token=123&expires_in=3600&refresh_token=456'
        access_token = self.service.get_access_token()
        self.assertEqual(access_token, '123')

    def dispatch_request(self, func):
        kwargs, method = func()
        return self.service.request(method, 'foo', **kwargs)

    @parameterize(input_product_gen())
    def test_request(self, func):
        kwargs, method = func()
        kwargs = kwargs.copy()
        r = self.service.request(method, 'foo', **kwargs)
        self.assert_ok(r)
