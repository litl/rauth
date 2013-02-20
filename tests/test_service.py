# -*- coding: utf-8 -*-
'''
    rauth.test_service
    ------------------

    Test suite for rauth.service.
'''

from base import RauthTestCase

from rauth.service import OAuth1Service, OAuth2Service, OflyService
from rauth.session import OAUTH2_DEFAULT_TIMEOUT
from rauth.utils import parse_utf8_qsl

from mock import patch

import requests
import json


class OflyServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # mock service for testing
        service = OflyService(name='example',
                              app_id='123',
                              app_secret='456',
                              authorize_url='http://example.com/authorize',
                              base_url='http://example.com/api/')
        self.service = service

    def test_init_with_base_url(self):
        service = OflyService(name='example',
                              app_id='123',
                              app_secret='456',
                              authorize_url='http://example.com/authorize',
                              base_url='http://example.com/api/')
        self.assertIsNotNone(service.base_url)
        self.assertEqual(service.base_url, 'http://example.com/api/')

    @patch.object(requests.Session, 'request')
    def test_get_with_base_url(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.get('mock_resource')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    def test_get_authorize_url(self):
        params = {'oflyRemoteUser': 'foobar',
                  'oflyCallbackUrl': 'http://example.com/redirect'}
        url = self.service.get_authorize_url(**params)
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
        r = self.service.request('GET', 'http://example.com/endpoint')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_get(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.get('http://example.com/endpoint')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_post(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.post('http://example.com/endpoint')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_put(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.put('http://example.com/endpoint')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_delete(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.delete('http://example.com/endpoint')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_head(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.head('http://example.com/endpoint')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_request_header_auth(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.request('GET',
                                 'http://example.com/endpoint',
                                 header_auth=True)
        self.assertTrue(r.status)
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_request_bad_response(self, mock_request):
        self.response.ok = False
        self.response.raise_for_status = self.raise_for_status
        mock_request.return_value = self.response

        response = self.service.get('http://example.com/endpoint')

        with self.assertRaises(Exception) as e:
            response.raise_for_status()
        self.assertEqual('Response not OK!', str(e.exception))


class OAuth2ServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # Use JSON as the response type for OAuth2.  RauthTestCase sets up
        # for OAuth1.
        self.response.content = \
            '{"access_token": "321", "token_type": "Bearer"}'
        self.response.headers = \
            {'content-type': 'application/json;charset=ISO-8859-1'}

        # mock service for testing
        service = OAuth2Service(
            name='example',
            client_id='123',
            client_secret='456',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            base_url='http://example.com/api/',
            access_token='987')
        self.service = service

    def test_init_with_access_token(self):
        service = OAuth2Service(
            name='example',
            client_id='123',
            client_secret='456',
            access_token_url='http://example.com/access_token',
            authorize_url='http://example.com/authorize',
            access_token='321')
        self.assertEqual(service.access_token, '321')

    def test_init_with_base_url(self):
        service = OAuth2Service(
            name='example',
            client_id='123',
            client_secret='456',
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
        r = self.service.get('mock_resource')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    def test_missing_client_creds(self):
        with self.assertRaises(TypeError):
            OAuth2Service()

    def test_get_authorize_url(self):
        authorize_url = \
            self.service.get_authorize_url(response_type='code')
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
        r = self.service.get_access_token(data={'code': '4242'})
        self.assertEqual(r.content, 'access_token=321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_sets_local_var(self, mock_request):
        mock_request.return_value = self.response
        self.service.get_access_token(data=dict(code='4242'))
        self.assertEqual(self.service.access_token, '321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_params(self, mock_request):
        mock_request.return_value = self.response
        r = self.service.get_access_token('GET', params={'code': '4242'})
        self.assertEqual(r.content, 'access_token=321')

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
        data = {'code': '4242', 'grant_type': 'refresh_token'}
        r = self.service.get_access_token(data=data)
        self.assertEqual(r.content, 'access_token=321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_client_credentials(self, mock_request):
        mock_request.return_value = self.response
        data = {'grant_type': 'client_credentials'}
        r = self.service.get_access_token(data=data)
        self.assertEqual(r.content, 'access_token=321')

    @patch.object(requests.Session, 'request')
    def test_request_with_access_token_override(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        method = 'GET'
        url = 'http://example.com/endpoint'
        r = self.service.request(method, url, access_token='420')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))
        mock_request.assert_called_with(method,
                                        url,
                                        params=dict(access_token='420'),
                                        timeout=OAUTH2_DEFAULT_TIMEOUT)

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        method = 'GET'
        url = 'http://example.com/endpoint'
        r = self.service.request(method, url)
        self.assertEqual({'status': 'ok'}, json.loads(r.content))
        mock_request.assert_called_with(method,
                                        url,
                                        params={'access_token': '987'},
                                        timeout=OAUTH2_DEFAULT_TIMEOUT)

    @patch.object(requests.Session, 'request')
    def test_get(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.get('http://example.com/endpoint',
                             access_token='321')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_post(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.post('http://example.com/endpoint',
                              access_token='321')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_put(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.put('http://example.com/endpoint',
                             access_token='321')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_delete(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        r = self.service.delete('http://example.com/endpoint',
                                access_token='321')
        self.assertEqual({'status': 'ok'}, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_request_bad_response(self, mock_request):
        self.response.ok = False
        self.response.raise_for_status = self.raise_for_status
        mock_request.return_value = self.response

        response = self.service.request('GET',
                                        'http://example.com/endpoint',
                                        access_token='321')
        self.assertFalse(response.ok)
        with self.assertRaises(Exception) as e:
            response.raise_for_status()
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
                             access_token='666')
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
        self.assertEqual('oauth_token=123&oauth_token_secret=456', response)

    @patch.object(requests.Session, 'request')
    def test_get_raw_request_token(self, mock_request):
        mock_request.return_value = self.response

        r = self.service.get_raw_request_token('GET')
        self.assertEqual(r.content, 'oauth_token=123&oauth_token_secret=456')

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

        request_token, request_token_secret = \
            self.service.get_request_token('POST', header_auth=True)
        self.assertEqual(request_token, '123')
        self.assertEqual(request_token_secret, '456')

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

        r = self.service.get_access_token('123', '456')
        self.assertEqual(r.content, 'oauth_token=123&oauth_token_secret=456')

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request):
        mock_request.return_value = self.response

        response = self.service.request(
            'GET', 'http://example.com/some/method').content
        self.assertIsNotNone(response)
        self.assertEqual('oauth_token=123&oauth_token_secret=456', response)

    @patch.object(requests.Session, 'request')
    def test_get(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.get('http://example.com/some/method',
                             access_token='123',
                             access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('oauth_token=123&oauth_token_secret=456', response)

    @patch.object(requests.Session, 'request')
    def test_post(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.post('http://example.com/some/method',
                              access_token='123',
                              access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('oauth_token=123&oauth_token_secret=456', response)

    @patch.object(requests.Session, 'request')
    def test_put(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.put('http://example.com/some/method',
                             access_token='123',
                             access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('oauth_token=123&oauth_token_secret=456', response)

    @patch.object(requests.Session, 'request')
    def test_delete(self, mock_request):
        mock_request.return_value = self.response

        response = \
            self.service.delete('http://example.com/some/method',
                                access_token='123',
                                access_token_secret='456').content
        self.assertIsNotNone(response)
        self.assertEqual('oauth_token=123&oauth_token_secret=456', response)

    @patch.object(requests.Session, 'request')
    def test_parse_optional_params_as_string(self, mock_request):
        mock_request.return_value = self.response

        r = self.service.get('http://example.com/some/method',
                             access_token='123',
                             access_token_secret='456',
                             params='oauth_verifier=foo')
        self.assertEqual('oauth_token=123&oauth_token_secret=456', r.content)

    @patch.object(requests.Session, 'request')
    def test_parse_optional_params_data(self, mock_request):
        mock_request.return_value = self.response

        r = self.service.post('http://example.com/some/method',
                              access_token='123',
                              access_token_secret='456',
                              data={'oauth_verifier': 'foo'})
        self.assertEqual('oauth_token=123&oauth_token_secret=456', r.content)

    @patch.object(requests.Session, 'request')
    def test_parse_optional_params_data_as_string(self, mock_request):
        mock_request.return_value = self.response

        r = self.service.post('http://example.com/some/method',
                              access_token='123',
                              access_token_secret='456',
                              data='oauth_verifier=foo')
        self.assertEqual('oauth_token=123&oauth_token_secret=456', r.content)

    @patch.object(requests.Session, 'request')
    def test_json_response(self, mock_request):
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response

        self.response.content = json.dumps({'a': 'b'})
        r = self.service.get_access_token(method='GET',
                                          request_token='123',
                                          request_token_secret='456')
        self.assertEqual({'a': 'b'}, json.loads(r.content))

        # test the case of a non-list, non-dict
        self.response.content = json.dumps(42)
        r = self.service.get_access_token(method='GET',
                                          request_token='123',
                                          request_token_secret='456')
        self.assertEqual(42, json.loads(r.content))

    @patch.object(requests.Session, 'request')
    def test_other_response(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = {'a': 'b'}
        r = self.service.get_access_token(method='GET',
                                          request_token='123',
                                          request_token_secret='456')
        self.assertEqual({'a': 'b'}, r.content)

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

        r = self.service.request('GET',
                                 '/',
                                 access_token='a',
                                 access_token_secret='b')

        expected = {u'username': u'joeshaw \xe9\xe9\xe9',
                    u'fullname': u'Joe Shaw'}
        self.assertEqual(parse_utf8_qsl(r.content), expected)

    @patch.object(requests.Session, 'request')
    def test_parse_utf8_qsl_dup_keys(self, mock_request):
        mock_request.return_value = self.response

        # test that we don't end up with deplicate keys
        self.response.content = '€=euro'

        r = self.service.request('GET',
                                 '/',
                                 access_token='a',
                                 access_token_secret='b')

        expected = {u'\u20ac': u'euro'}
        self.assertEqual(parse_utf8_qsl(r.content), expected)

    def test_missing_request_token_url(self):
        service = OAuth1Service(None, None)
        with self.assertRaises(TypeError) as e:
            service.get_request_token()
        self.assertEqual(str(e.exception),
                         'request_token_url must not be None')

    def test_missing_access_token_url(self):
        service = OAuth1Service(None, None)
        with self.assertRaises(TypeError) as e:
            service.get_access_token(None, None)
        self.assertEqual(str(e.exception), 'access_token_url must not be None')
