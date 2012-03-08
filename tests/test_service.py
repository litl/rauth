'''
    webauth.test_oauth
    ------------------

    Test suite for webauth.service.
'''

from base import WebauthTestCase
from webauth.service import OAuth1Service, OAuth2Service

from mock import Mock, patch

import requests
import json


class OAuth2ServiceTestCase(WebauthTestCase):
    def setUp(self):
        WebauthTestCase.setUp(self)

        # mock service for testing
        service = OAuth2Service(
                'example',
                consumer_key='123',
                consumer_secret='456',
                access_token_url='http://example.com/access_token',
                authorize_url='http://example.com/authorize')
        self.service = service

        def raise_for_status(*args, **kwargs):
            raise Exception('Response not OK!')

        # mock response for testing
        response = Mock()
        response.content = 'access_token=321'
        response.ok = True
        response.status_code = 200
        response.raise_for_status = lambda *args, **kwargs: raise_for_status()
        self.response = response

    def test_init_with_access_token(self):
        service = OAuth2Service(
                'example',
                consumer_key='123',
                consumer_secret='456',
                access_token_url='http://example.com/access_token',
                authorize_url='http://example.com/authorize',
                access_token='321')
        self.assertEqual(service.access_token, '321')

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
        response = self.service.get_access_token(code='4242')
        self.assertEqual(response['access_token'], '321')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_bad_response(self, mock_request):
        self.response.ok = False
        mock_request.return_value = self.response
        try:
            self.service.get_access_token(code='4242')
        except Exception, e:
            self.assertEqual('Response not OK!', str(e))

    @patch.object(requests.Session, 'request')
    def test_get_access_token_grant_type(self, mock_request):
        mock_request.return_value = self.response
        response = self.service.get_access_token(code='4242',
                                                grant_type='refresh_token')
        self.assertEqual(response['access_token'], '321')

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        mock_request.return_value = self.response
        response = self.service.request('GET',
                                        'http://example.com/endpoint',
                                         access_token='321')
        self.assertEqual(response['status'], 'ok')

        # test here again to make sure the access token was set
        response = self.service.request('GET',
                                        'http://example.com/endpoint')
        self.assertEqual(response['status'], 'ok')

    @patch.object(requests.Session, 'request')
    def test_request_bad_response(self, mock_request):
        self.response.ok = False
        mock_request.return_value = self.response
        try:
            self.service.request('GET',
                                 'http://example.com/endpoint',
                                  access_token='321')
        except Exception, e:
            self.assertEqual('Response not OK!', str(e))

    @patch.object(requests.Session, 'request')
    def test_request_missing_acccess_token(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        mock_request.return_value = self.response
        try:
            self.service.request('GET', 'http://example.com/endpoint')
        except Exception, e:
            self.assertEqual('Access token must be set!', str(e))


class OAuth1ServiceTestCase(WebauthTestCase):
    def setUp(self):
        WebauthTestCase.setUp(self)

        # mock service for testing
        service = OAuth1Service(
                'example',
                consumer_key='123',
                consumer_secret='456',
                request_token_url='http://example.com/request_token',
                access_token_url='http://example.com/access_token',
                authorize_url='http://example.com/authorize')
        self.service = service

        def raise_for_status(*args, **kwargs):
            raise Exception('Response not OK!')

        # mock response for testing
        response = Mock()
        response.content = 'oauth_token=123&oauth_token_secret=456'
        response.ok = True
        response.raise_for_status = lambda *args, **kwargs: raise_for_status()
        self.response = response

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
        mock_request.return_value = self.response

        try:
            self.service.get_request_token('GET')
        except Exception, e:
            self.assertEqual('Response not OK!', str(e))

        self.assertRaises(Exception, self.service.get_request_token, ('GET'))

    def test_get_authorize_url(self):
        authorize_url = self.service.get_authorize_url(request_token='123')
        expected_url = 'http://example.com/authorize?oauth_token=123'
        self.assertEqual(expected_url, authorize_url)

    def test_get_authorize_url_with_callback(self):
        callback = 'http://example.com/callback'
        authorize_url = self.service.get_authorize_url(request_token='123',
                                                       oauth_callback=callback)
        expected_url = 'http://example.com/authorize?oauth_token=123&' \
                'oauth_callback=http%3A%2F%2Fexample.com%2Fcallback'
        self.assertEqual(expected_url, authorize_url)

    @patch.object(requests.Session, 'request')
    def test_get_access_token(self, mock_request):
        mock_request.return_value = self.response

        access_resp = self.service.get_access_token(request_token='123',
                                                    request_token_secret='456',
                                                    http_method='GET')
        self.assertEqual(access_resp['oauth_token'], '123')
        self.assertEqual(access_resp['oauth_token_secret'], '456')

    @patch.object(requests.Session, 'request')
    def test_get_access_token_bad_response(self, mock_request):
        self.response.ok = False
        mock_request.return_value = self.response

        try:
            self.service.get_access_token('123','456', 'GET')
        except Exception, e:
            self.assertEqual('Response not OK!', str(e))

        self.assertRaises(Exception,
                          self.service.get_access_token,
                          ('123','456', 'GET'))

    def test_get_authenticated_session(self):
        auth_session = \
            self.service.get_authenticated_session(access_token='123',
                                                   access_token_secret='456')
        self.assertTrue(auth_session is not None)

    @patch.object(requests.Session, 'request')
    def test_json_response(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = json.dumps({'a': 'b'})
        access_resp = self.service.get_access_token('123','456', 'GET')
        self.assertEqual({'a': 'b'}, access_resp)

    @patch.object(requests.Session, 'request')
    def test_other_response(self, mock_request):
        mock_request.return_value = self.response

        self.response.content = {'a': 'b'}
        access_resp = self.service.get_access_token('123','456', 'GET')
        self.assertEqual({'a': 'b'}, access_resp)
