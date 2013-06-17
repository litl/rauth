# -*- coding: utf-8 -*-
'''
    rauth.test_service_oauth2
    -------------------------

    Test suite for rauth.service.OAuth2Service.
'''

from base import RauthTestCase
from test_service import HttpMixin, ServiceMixin, RequestMixin

from rauth.service import OAuth2Service
from rauth.session import OAUTH2_DEFAULT_TIMEOUT, OAuth2Session
from rauth.compat import basestring, parse_qsl

from copy import deepcopy
from mock import patch

import requests

import json
import pickle


class OAuth2ServiceTestCase(RauthTestCase, ServiceMixin, HttpMixin,
                            RequestMixin):
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
                     bearer_auth=False,
                     **kwargs):
        mock_request.return_value = self.response

        url = self.session._set_url(url)

        service = OAuth2Service(self.client_id,
                                self.client_secret,
                                access_token_url=self.access_token_url,
                                authorize_url=self.authorize_url,
                                base_url=self.base_url)

        session = service.get_session(self.access_token)
        r = session.request(method,
                            url,
                            bearer_auth=bearer_auth,
                            **deepcopy(kwargs))

        kwargs.setdefault('params', {})

        if isinstance(kwargs.get('params', {}), basestring):
            kwargs['params'] = dict(parse_qsl(kwargs['params']))

        if bearer_auth and self.access_token is not None:
            bearer_token = 'Bearer {token}'.format(token=self.access_token)
            bearer_header = {'Authorization': bearer_token}
            kwargs.setdefault('headers', {})
            kwargs['headers'].update(bearer_header)
        else:
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

    def test_get_access_token_with_json_decoder(self):
        self.response.content = json.dumps({'access_token': '123',
                                            'expires_in': '3600',
                                            'refresh_token': '456'})
        access_token = self.service.get_access_token(decoder=json.loads)
        self.assertEqual(access_token, '123')

    def test_request_with_bearer_auth(self):
        r = self.session.request('GET',
                                 'http://example.com/',
                                 bearer_auth=True)
        self.assert_ok(r)

    def test_get_auth_session(self):
        self.response.content = \
            'access_token=123&expires_in=3600&refresh_token=456'
        s = self.service.get_auth_session()
        self.assertIsInstance(s, OAuth2Session)

    def test_pickle_session(self):
        session = pickle.loads(pickle.dumps(self.session))

        # Add the fake request back to the session
        session.request = self.fake_request
        r = session.request('GET', 'http://example.com/', header_auth=True)
        self.assert_ok(r)
