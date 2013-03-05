# -*- coding: utf-8 -*-
'''
    rauth.test_service_oauth2
    -------------------------

    Test suite for rauth.service.OAuth2Service.
'''

from base import RauthTestCase
from test_service import HttpMixin, RequestMixin

from rauth.service import OAuth2Service
from rauth.session import OAUTH2_DEFAULT_TIMEOUT, OAuth2Session

from urlparse import parse_qsl

from copy import deepcopy
from mock import patch

import requests


class OAuth2ServiceTestCase(RauthTestCase, RequestMixin, HttpMixin):
    client_id = '000'
    client_secret = '111'
    access_token = '123'

    def setUp(self):
        RauthTestCase.setUp(self)

        self.access_token_url = 'https://example.com/access'
        self.authorize_url = 'https://example.com/authorize'
        self.base_url = 'https://example/api/'

        self.service = OAuth2Service(self.client_id,
                                     self.client_secret,
                                     access_token_url=self.access_token_url,
                                     authorize_url=self.authorize_url,
                                     base_url=self.base_url)

        self.session = self.service.get_session(self.access_token)

        # patches
        self.session.request = self.fake_request
        self.service.get_session = self.fake_get_session

    @patch.object(requests.Session, 'request')
    def fake_request(self,
                     method,
                     url,
                     mock_request,
                     **kwargs):
        mock_request.return_value = self.response

        url = self.session._set_url(url)

        service = OAuth2Service(self.client_id,
                                self.client_secret,
                                access_token_url=self.access_token_url,
                                authorize_url=self.authorize_url,
                                base_url=self.base_url)

        session = service.get_session(self.access_token)
        r = session.request(method, url, **deepcopy(kwargs))

        if isinstance(kwargs.get('params', {}), basestring):
            kwargs['params'] = dict(parse_qsl(kwargs['params']))

        kwargs.setdefault('params', {})
        kwargs['params'].update({'access_token': self.access_token})

        mock_request.assert_called_with(method,
                                        url,
                                        timeout=OAUTH2_DEFAULT_TIMEOUT,
                                        **kwargs)
        return r

    def fake_get_session(self, token=None):
        return self.session

    def test_get_session(self):
        s = self.service.get_session()
        self.assertIsInstance(s, OAuth2Session)

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

    def test_get_auth_session(self):
        self.response.content = \
            'access_token=123&expires_in=3600&refresh_token=456'
        s = self.service.get_auth_session()
        self.assertIsInstance(s, OAuth2Session)
