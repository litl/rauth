# -*- coding: utf-8 -*-
'''
    rauth.test_service
    ------------------

    Test suite for rauth.service.
'''

from base import RauthTestCase
from rauth.service import (OAuth1Service, OAuth2Service, OflyService,
                           DEFAULT_TIMEOUT)

from datetime import datetime
from mock import patch

import requests
import json


class OflyServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # mock service for testing
        service = OflyService(name='example',
                              consumer_key='123',
                              consumer_secret='456',
                              authorize_url='http://example.com/authorize',
                              base_url='http://example.com/api/')
        self.service = service

    def test_init_with_base_url(self):
        service = OflyService(name='example',
                              consumer_key='123',
                              consumer_secret='456',
                              authorize_url='http://example.com/authorize',
                              base_url='http://example.com/api/')
        self.assertIsNotNone(service.base_url)
        self.assertEqual(service.base_url, 'http://example.com/api/')

    @patch.object(requests.Session, 'request')
    def test_get_with_base_url(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.get('mock_resource').content
        self.assertEqual(response['status'], 'ok')

    def test_get_authorize_url(self):
        url = self.service.get_authorize_url(
            remote_user='foobar',
            redirect_uri='http://example.com/redirect')
        self.assertIn('ApiSig=', url)
        self.assertIn('oflyAppId=123', url)
        self.assertIn('oflyCallbackUrl=http://example.com/redirect', url)
        self.assertIn('oflyHashMeth=SHA1', url)
        self.assertIn('oflyRemoteUser=foobar', url)
        self.assertIn('oflyTimestamp=', url)

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.request('GET',
                                        'http://example.com/endpoint').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_get(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.get('http://example.com/endpoint').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_post(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.post('http://example.com/endpoint').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_put(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.put('http://example.com/endpoint').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_delete(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.delete('http://example.com/endpoint').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_head(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.head('http://example.com/endpoint').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_request_header_auth(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.request('GET',
                                        'http://example.com/endpoint',
                                        header_auth=True).content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_request_bad_response(self, mock_request):
        self.response.ok = False
        self.response.raise_for_status = self.raise_for_status
        mock_request.return_value = self.response

        response = self.service.get('http://example.com/endpoint')

        with self.assertRaises(Exception) as e:
            response.response.raise_for_status()
        self.assertEqual('Response not OK!', str(e.exception))

    def test_micro_to_milliseconds(self):
        microseconds = datetime.utcnow().microsecond
        milliseconds = self.service._micro_to_milliseconds(microseconds)
        self.assertTrue(len(str(milliseconds)) < 4)


class OAuth2ServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # mock service for testing
        service = OAuth2Service(
            name='example',
            consumer_key='123',
            consumer_secret='456',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            base_url='http://example.com/api/',
            access_token='987')
        self.service = service

    def test_init_with_access_token(self):
        service = OAuth2Service(
            name='example',
            consumer_key='123',
            consumer_secret='456',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            access_token='321')
        self.assertEqual(service.access_token, '321')

    def test_init_with_base_url(self):
        service = OAuth2Service(
            name='example',
            consumer_key='123',
            consumer_secret='456',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            base_url='http://example.com/api/')
        self.assertIsNotNone(service.base_url)
        self.assertEqual(service.base_url, 'http://example.com/api/')

    @patch.object(requests.Session, 'request')
    def test_get_with_access_token(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.get('mock_resource').content
        self.assertEqual(response['status'], 'ok')

    def test_missing_client_creds(self):
        with self.assertRaises(TypeError) as e:
            OAuth2Service()
        self.assertEqual(str(e.exception),
                         'client_id and client_secret must not be None')

    def test_get_authorize_url(self):
        authorize_url = self.service.get_authorize_url()
        expected_url = \
            'http://example.com/authorize?response_type=code&client_id=123'
        self.assertEqual(expected_url, authorize_url)

    def test_get_authorize_url_response_type(self):
        authorize_url = self.service.get_authorize_url(response_type='token')
        expected_url = \
            'http://example.com/authorize?response_type=token&client_id=123'
        self.assertEqual(expected_url, authorize_url)

    @patch.object(requests.Session, 'request')
    def test_get_access_token(self, mock_request):
        mock_request.return_value = self.response
        response = \
            self.service.get_access_token(data=dict(code='4242')).content
        self.assertEqual(response['access_token'], '321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_sets_local_var(self, mock_request):
        mock_request.return_value = self.response
        self.service.get_access_token(data=dict(code='4242'))
        self.assertEqual(self.service.access_token, '321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_params(self, mock_request):
        mock_request.return_value = self.response
        response = \
            self.service.get_access_token('GET',
                                          params=dict(code='4242')).content
        self.assertEqual(response['access_token'], '321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_bad_response(self, mock_request):
        self.response.ok = False
        self.response.raise_for_status = self.raise_for_status
        mock_request.return_value = self.response

        with self.assertRaises(NameError) as e:
            self.service.get_access_token(code='4242')
        self.assertEqual('Either params or data dict missing',
                         str(e.exception))

    @patch.object(requests.Session, 'request')
    def test_get_access_token_grant_type(self, mock_request):
        mock_request.return_value = self.response
        data = dict(code='4242', grant_type='refresh_token')
        response = self.service.get_access_token(data=data).content
        self.assertEqual(response['access_token'], '321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_client_credentials(self, mock_request):
        mock_request.return_value = self.response
        data = dict(grant_type='client_credentials')
        response = self.service.get_access_token(data=data).content
        self.assertEqual(response['access_token'], '321')

    @patch.object(requests.Session, 'request')
    def test_request_with_access_token_override(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        method = 'GET'
        url = 'http://example.com/endpoint'
        response = self.service.request(method, url, access_token='420')
        self.assertEqual(response.content['status'], 'ok')
        mock_request.assert_called_with(method,
                                        url,
                                        params=dict(access_token='420'),
                                        timeout=DEFAULT_TIMEOUT)

    @patch.object(requests.Session, 'request')
    def test_request_with_no_access_token(self, mock_request):
        self.service.access_token = None
        with self.assertRaises(TypeError) as e:
            self.service.request('GET', 'http://example.com/endpoint')
        self.assertEqual('access_token must not be None',
                         str(e.exception))

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        method = 'GET'
        url = 'http://example.com/endpoint'
        response = self.service.request(method, url).content
        self.assertEqual(response['status'], 'ok')
        mock_request.assert_called_with(method,
                                        url,
                                        params=dict(access_token='987'),
                                        timeout=DEFAULT_TIMEOUT)

    @patch.object(requests.Session, 'request')
    def test_get(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.get('http://example.com/endpoint',
                                    access_token='321').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_post(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.post('http://example.com/endpoint',
                                     access_token='321').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_put(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.put('http://example.com/endpoint',
                                    access_token='321').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_delete(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.delete('http://example.com/endpoint',
                                       access_token='321').content
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_request_bad_response(self, mock_request):
        self.response.ok = False
        self.response.raise_for_status = self.raise_for_status
        mock_request.return_value = self.response

        response = self.service.request('GET',
                                        'http://example.com/endpoint',
                                        access_token='321')
        self.assertFalse(response.response.ok)
        with self.assertRaises(Exception) as e:
            response.response.raise_for_status()
        self.assertEqual('Response not OK!', str(e.exception))


class OAuth1ServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # mock service for testing
        service = OAuth1Service(
            name='example',
            consumer_key='123',
            consumer_secret='456',
            request_token_url='http://example.com/request_token',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            base_url='http://example.com/api/',
            access_token='321',
            access_token_secret='123')
        self.service = service

        # mock response content
        self.response.content = 'oauth_token=123&oauth_token_secret=456'

    def test_init_with_access_token(self):
        service = OAuth1Service(
            name='example',
            consumer_key='123',
            consumer_secret='456',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            access_token='321',
            access_token_secret='123')
        self.assertEqual(service.access_token, '321')
        self.assertEqual(service.access_token_secret, '123')

    def test_init_with_base_url(self):
        service = OAuth1Service(
            name='example',
            consumer_key='123',
            consumer_secret='456',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            base_url='http://example.com/api/',
            access_token_secret='123')
        self.assertEqual(service.base_url, 'http://example.com/api/')

    @patch.object(requests.Session, 'request')
    def test_request_access_token_missing(self, mock_request):
        mock_request.return_value = self.response

        with self.assertRaises(TypeError) as e:
            self.service.get('http://example.com/some/method',
                             access_token_secret='666').content
        self.assertEqual('Either both or neither access_token and '
                         'access_token_secret must be supplied',
                         str(e.exception))

    @patch.object(requests.Session, 'request')
    def test_request_access_token_secret_missing(self, mock_request):
        mock_request.return_value = self.response

        with self.assertRaises(TypeError) as e:
            self.service.get('http://example.com/some/method',
                             access_token='666').content
        self.assertEqual('Either both or neither access_token and '
                         'access_token_secret must be supplied',
                         str(e.exception))

    @patch.object(requests.Session, 'request')
    def test_request_with_access_token_override(self, mock_request):
        mock_request.return_value = self.response
        response = self.service.request('GET',
                                        'http://example.com/some/method',
                                        access_token_secret='777',
                                        access_token='666').content
        self.assertIsNotNone(response)
        self.assertEqual('123', response['oauth_token'])
        self.assertEqual('456', response['oauth_token_secret'])

    @patch.object(OAuth1Service, '_construct_session')
    def test_request_with_access_token_session(self, _construct_session):
        self.service.request('GET',
                             'http://example.com/some/method',
                             access_token_secret='777',
                             access_token='666')
        session_params = dict(access_token='666',
                              access_token_secret='777',
                              header_auth=self.service.header_auth)
        _construct_session.assert_called_with(**session_params)

    @patch.object(requests.Session, 'request')
    def test_get_raw_request_token(self, mock_request):
        mock_request.return_value = self.response

        resp = self.service.get_raw_request_token('GET')
        self.assertEqual(resp, {'oauth_token': '123',
                                'oauth_token_secret': '456'})

    @patch.object(requests.Session, 'request')
    def test_get_request_token(self, mock_request):
        mock_request.return_value = self.response

        request_token, request_token_secret = \
            self.service.get_request_token('GET')
        self.assertEqual(request_token, '123')
        self.assertEqual(request_token_secret, '456')

    @patch.object(requests.Session, 'request')
    def test_get_request_token_post(self, mock_request):
        mock_request.return_value = self.response

        request_token, request_token_secret = \
            self.service.get_request_token('POST')
        self.assertEqual(request_token, '123')
        self.assertEqual(request_token_secret, '456')

    @patch.object(requests.Session, 'request')
    def test_get_request_token_header_auth(self, mock_request):
        mock_request.return_value = self.response

        self.service.header_auth = True
        request_token, request_token_secret = \
            self.service.get_request_token('POST')
        self.assertEqual(request_token, '123')
        self.assertEqual(request_token_secret, '456')

    @patch.object(requests.Session, 'request')
    def test_get_request_token_bad_response(self, mock_request):
        self.response.ok = False
        self.response.content = 'Oops, something went wrong :('
        self.response.raise_for_status = self.raise_for_status
        mock_request.return_value = self.response

        with self.assertRaises(Exception) as e:
            self.service.get_request_token('GET')
        self.assertEqual(str(e.exception), 'Response not OK!')

    def test_get_authorize_url(self):
        authorize_url = self.service.get_authorize_url(request_token='123')
        expected_url = 'http://example.com/authorize?oauth_token=123'
        self.assertEqual(expected_url, authorize_url)

    def test_get_authorize_url_with_additional_param(self):
        val = 'http://example.com/something'
        authorize_url = self.service.get_authorize_url(request_token='123',
                                                       additional_param=val)
        expected_url = 'http://example.com/authorize?oauth_token=123&' \
                       'additional_param=http%3A%2F%2Fexample.com%2Fsomething'
        self.assertEqual(expected_url, authorize_url)

    @patch.object(requests.Session, 'request')
    def test_get_access_token(self, mock_request):
        mock_request.return_value = self.response

        access_resp = self.service.get_access_token(request_token='123',
                                                    request_token_secret='456',
                                                    method='GET').content
        self.assertEqual(access_resp['oauth_token'], '123')
        self.assertEqual(access_resp['oauth_token_secret'], '456')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_bad_response(self, mock_request):
        self.response.ok = False
        self.response.content = \
            json.dumps(dict(error='Oops, something went wrong :('))
        mock_request.return_value = self.response

        response = self.service.get_access_token('GET',
                                                 request_token='123',
                                                 request_token_secret='456')

        expected = dict(error='Oops, something went wrong :(')
        self.assertEqual(response.content, expected)

    def test_get_authenticated_session(self):
        auth_session = \
            self.service.get_authenticated_session(access_token='123',
                                                   access_token_secret='456')
        self.assertIsNotNone(auth_session)

    @patch.object(requests.Session, 'request')
    def test_use_authenticated_session(self, mock_request):
        mock_request.return_value = self.response

        auth_session = \
            self.service.get_authenticated_session(access_token='123',
                                                   access_token_secret='456')

        response = auth_session.get('http://example.com/foobar').content
        self.assertIsNotNone(response)
        self.assertEqual('oauth_token=123&oauth_token_secret=456', response)

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request):
        mock_request.return_value = self.response

        response = self.service.request(
            'GET', 'http://example.com/some/method').content
        self.assertIsNotNone(response)
        self.assertEqual('123', response['oauth_token'])
        self.assertEqual('456', response['oauth_token_secret'])

    @patch.object(requests.Session, 'request')
    def test_get(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.get('http://example.com/some/method',
                             access_token='123',
                             access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('123', response['oauth_token'])
        self.assertEqual('456', response['oauth_token_secret'])

    @patch.object(requests.Session, 'request')
    def test_post(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.post('http://example.com/some/method',
                              access_token='123',
                              access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('123', response['oauth_token'])
        self.assertEqual('456', response['oauth_token_secret'])

    @patch.object(requests.Session, 'request')
    def test_put(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.put('http://example.com/some/method',
                             access_token='123',
                             access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('123', response['oauth_token'])
        self.assertEqual('456', response['oauth_token_secret'])

    @patch.object(requests.Session, 'request')
    def test_delete(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.delete('http://example.com/some/method',
                                access_token='123',
                                access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('123', response['oauth_token'])
        self.assertEqual('456', response['oauth_token_secret'])

    @patch.object(requests.Session, 'request')
    def test_json_response(self, mock_request):
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response

        self.response.content = json.dumps({'a': 'b'})
        access_resp = self.service.get_access_token(method='GET',
                                                    request_token='123',
                                                    request_token_secret='456')
        self.assertEqual({'a': 'b'}, access_resp.content)

        # test the case of a non-list, non-dict
        self.response.content = json.dumps(42)
        access_resp = self.service.get_access_token(method='GET',
                                                    request_token='123',
                                                    request_token_secret='456')
        self.assertEqual(42, access_resp.content)

    @patch.object(requests.Session, 'request')
    def test_other_response(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = {'a': 'b'}
        access_resp = self.service.get_access_token(method='GET',
                                                    request_token='123',
                                                    request_token_secret='456')
        self.assertEqual({'a': 'b'}, access_resp.content)

    @patch.object(requests.Session, 'request')
    def test_parse_utf8_qsl_non_unicode(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = 'oauth_token=\xc3\xbc&oauth_token_secret=b'

        request_token, request_token_secret = \
            self.service.get_request_token('GET')
        self.assertEqual(request_token, u'\xfc')
        self.assertEqual(request_token_secret, 'b')

    @patch.object(requests.Session, 'request')
    def test_parse_utf8_qsl_unicode_encoded(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = u'oauth_token=\xfc&oauth_token_secret=b'

        request_token, request_token_secret = \
            self.service.get_request_token('GET')
        self.assertEqual(request_token, u'\xfc')
        self.assertEqual(request_token_secret, 'b')

    @patch.object(requests.Session, 'request')
    def test_parse_utf8_qsl_unicode(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = u'oauth_token=ü&oauth_token_secret=b'

        request_token, request_token_secret = \
            self.service.get_request_token('GET')
        self.assertEqual(request_token, u'\xfc')
        self.assertEqual(request_token_secret, 'b')

    @patch.object(requests.Session, 'request')
    def test_parse_utf8_qsl_joe(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = 'fullname=Joe%20Shaw&username=' \
                                'joeshaw%20%C3%A9%C3%A9%C3%A9'

        response = self.service.request('GET',
                                        '/',
                                        access_token='a',
                                        access_token_secret='b')

        expected = {u'username': u'joeshaw \xe9\xe9\xe9',
                    u'fullname': u'Joe Shaw'}
        self.assertEqual(response.content, expected)

    @patch.object(requests.Session, 'request')
    def test_parse_utf8_qsl_dup_keys(self, mock_request):
        mock_request.return_value = self.response

        # test that we don't end up with deplicate keys
        self.response.content = '€=euro'

        response = self.service.request('GET',
                                        '/',
                                        access_token='a',
                                        access_token_secret='b')

        expected = {u'\u20ac': u'euro'}
        self.assertEqual(response.content, expected)

    def test_missing_request_token_url(self):
        service = OAuth1Service(None, None)
        with self.assertRaises(TypeError) as e:
            service.get_request_token()
        self.assertEqual(str(e.exception),
                         'request_token_url must not be None')

    def test_missing_access_token_url(self):
        service = OAuth1Service(None, None)
        with self.assertRaises(TypeError) as e:
            service.get_access_token()
        self.assertEqual(str(e.exception),
                         'access_token_url must not be None')
