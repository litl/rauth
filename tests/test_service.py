# -*- coding: utf-8 -*-
'''
    rauth.test_service
    ------------------

    Test suite for rauth.service.
'''

from base import RauthTestCase

from rauth.service import OAuth1Service, OAuth2Service, OflyService, Service
from rauth.session import (OAUTH1_DEFAULT_TIMEOUT, OAUTH2_DEFAULT_TIMEOUT,
                           OFLY_DEFAULT_TIMEOUT, OAuth1Session, OAuth2Session,
                           OflySession, _get_sorted_params)
from rauth.utils import FORM_URLENCODED

from datetime import datetime
from hashlib import sha1
from urlparse import parse_qsl

from mock import patch

import rauth

import requests

import json


class MutableDatetime(datetime):
    def __new__(cls, *args, **kwargs):
        return datetime.__new__(datetime, *args, **kwargs)


class MockSha1(object):
    def __new__(cls, *args, **kwargs):
            return cls

    @staticmethod
    def hexdigest():
        return 'foo'


class MockMd5(object):
    def __new__(cls, *args, **kwargs):
            return cls

    @staticmethod
    def hexdigest():
        return 'foo'


class HttpMixin(object):
    http_url = 'http://example.com/'

    def assert_ok(self, r):
        self.assertEqual(json.loads(r.content), {'status': 'ok'})

    def test_request(self):
        r = self.service.request('GET', 'foo')
        self.assert_ok(r)

    def test_head(self):
        r = self.service.head(self.http_url)
        self.assert_ok(r)

    def test_get(self):
        r = self.service.get(self.http_url)
        self.assert_ok(r)

    def test_post(self):
        r = self.service.post(self.http_url)
        self.assert_ok(r)

    def test_put(self):
        r = self.service.put(self.http_url)
        self.assert_ok(r)

    def test_delete(self):
        r = self.service.delete(self.http_url)
        self.assert_ok(r)


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
                     realm=None,
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

        oauth_params = {'oauth_consumer_key': session.consumer_key,
                        'oauth_nonce': fake_nonce,
                        'oauth_signature_method': fake_sig_meth,
                        'oauth_timestamp': fake_time,
                        'oauth_token': access_token,
                        'oauth_version': session.VERSION,
                        'oauth_signature': fake_sig}

        if header_auth:
            auth_string = 'OAuth realm="{realm}",'
            auth_string += 'oauth_nonce="{oauth_nonce}",'
            auth_string += 'oauth_timestamp="{oauth_timestamp}",'
            auth_string += 'oauth_consumer_key="{oauth_consumer_key}",'
            auth_string += 'oauth_signature_method="{oauth_signature_method}",'
            auth_string += 'oauth_version="{oauth_version}",'
            auth_string += 'oauth_token="{oauth_token}",'
            auth_string += 'oauth_signature="{oauth_signature}"'

            auth_string = \
                auth_string.format(realm=realm or '',
                                   oauth_nonce=fake_nonce,
                                   oauth_timestamp=fake_time,
                                   oauth_consumer_key=session.consumer_key,
                                   oauth_signature_method=fake_sig_meth,
                                   oauth_version=session.VERSION,
                                   oauth_token=access_token,
                                   oauth_signature=fake_sig)

            headers = {'Authorization': auth_string}

            kwargs.setdefault('headers', {})
            kwargs['headers'].update(**headers)
        elif method in ('POST', 'PUT'):
            headers = {'Content-Type': FORM_URLENCODED}
            kwargs.setdefault('data', {})
            if isinstance(kwargs['data'], str):
                kwargs['data'] = dict(parse_qsl(kwargs['data']))
            kwargs['data'].update(**oauth_params)
            kwargs.setdefault('headers', {})
            kwargs['headers'].update(**headers)
        else:
            kwargs.setdefault('params', {})
            if isinstance(kwargs['params'], str):
                kwargs['params'] = dict(parse_qsl(kwargs['params']))
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
        resp = 'access_token=123'
        self.response.content = resp
        r = self.service.get_raw_access_token()
        self.assertEqual(r.content, resp)

    def test_get_raw_access_token_with_params(self):
        resp = 'access_token=123'
        self.response.content = resp
        r = self.service.get_raw_access_token(params={'a': 'b'})
        self.assertEqual(r.content, resp)

    def test_get_access_token(self):
        self.response.content = 'access_token=123'
        access_token = self.service.get_access_token()
        self.assertEqual(access_token, '123')


class OflyServiceTestCase(RauthTestCase, HttpMixin):
    def setUp(self):
        RauthTestCase.setUp(self)

        self.authorize_url = 'http://example.com/authorize'
        self.base_url = 'http://example.com/api/'

        self.service = OflyService('000',
                                   '111',
                                   name='service',
                                   authorize_url=self.authorize_url,
                                   base_url=self.base_url)

        self.service.request = self.fake_request

    @patch('rauth.session.datetime', MutableDatetime)
    @patch('rauth.session.md5', MockMd5)
    @patch('rauth.session.sha1', MockSha1)
    @patch.object(requests.Session, 'request')
    def fake_request(self,
                     method,
                     url,
                     mock_request,
                     header_auth=False,
                     hash_meth='sha1',
                     **kwargs):
        MutableDatetime.utcnow = classmethod(lambda cls: datetime(1900, 1, 1))
        mock_request.return_value = self.response

        session = self.service.get_session()
        service = Service('service',
                          self.service.base_url,
                          self.service.authorize_url)
        r = service.request(session,
                            method,
                            url,
                            header_auth=header_auth,
                            hash_meth=hash_meth,
                            **kwargs)

        url = service._set_url(url)

        ofly_params = {'oflyAppId': self.service.app_id,
                       'oflyHashMeth': hash_meth.upper(),
                       'oflyTimestamp': '1900-01-01T00:00:00.0Z',
                       'oflyApiSig': 'foo'}

        kwargs.setdefault('params', {})

        if header_auth:
            kwargs.setdefault('headers', {})
            auth_header = _get_sorted_params(ofly_params)
            kwargs['headers'].update({'Authorization': auth_header})
        else:
            kwargs['params'].update(**ofly_params)
            kwargs['params'] = _get_sorted_params(kwargs['params'])

        mock_request.assert_called_with(method,
                                        url,
                                        timeout=OFLY_DEFAULT_TIMEOUT,
                                        **kwargs)
        return r

    def test_get_session(self):
        s = self.service.get_session()
        self.assertIsInstance(s, OflySession)

    @patch('rauth.session.datetime', MutableDatetime)
    @patch('rauth.session.sha1', MockSha1)
    def test_get_authorize_url(self):
        MutableDatetime.utcnow = classmethod(lambda cls: datetime(1900, 1, 1))

        params = 'oflyApiSig=foo&'
        params += 'oflyAppId={0}&'.format(self.service.app_id)
        params += 'oflyHashMeth=SHA1&'
        params += 'oflyTimestamp=1900-01-01T00:00:00.0Z'

        expected_url = 'http://example.com/authorize?'

        url = self.service.get_authorize_url()
        self.assertEqual(url, expected_url + params)

    def test_request_with_header_auth(self):
        r = self.service.request('GET',
                                 'http://example.com/',
                                 header_auth=True)
        self.assert_ok(r)

    def test_request_with_md5(self):
        r = self.service.request('GET',
                                 'http://example.com/',
                                 hash_meth='md5')
        self.assert_ok(r)

    def test_request_with_bad_hash_meth(self):
        with self.assertRaises(TypeError) as e:
            self.service.request('GET',
                                 'http://example.com/',
                                 hash_meth='foo')
        self.assertEqual(str(e.exception),
                         'hash_meth must be one of "sha1", "md5"')
