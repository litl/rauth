# -*- coding: utf-8 -*-
'''
    rauth.test_oauth
    ----------------

    Test suite for rauth.service.
'''

from base import RauthTestCase
from rauth.service import OAuth1Service, OAuth2Service, OflyService

from datetime import datetime
from mock import patch

import requests
import json


class OflyServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # mock service for testing
        service = OflyService(
                'example',
                consumer_key='123',
                consumer_secret='456',
                authorize_url='http://example.com/authorize')
        self.service = service

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

        with self.assertRaises(Exception) as e:
            self.service.get('http://example.com/endpoint')
            self.assertEqual('Response not OK!', str(e))

    def test_micro_to_milliseconds(self):
        microseconds = datetime.utcnow().microsecond
        milliseconds = self.service._micro_to_milliseconds(microseconds)
        self.assertTrue(len(str(milliseconds)) < 4)


class OAuth2ServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # mock service for testing
        service = OAuth2Service(
                'example',
                consumer_key='123',
                consumer_secret='456',
                access_token_url='http://example.com/access_token',
                authorize_url='http://example.com/authorize')
        self.service = service

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
        response = \
                self.service.get_access_token(data=dict(code='4242')).content
        self.assertEqual(response['access_token'], '321')

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

        with self.assertRaises(Exception) as e:
            self.service.get_access_token(code='4242')
            self.assertEqual('Response not OK!', str(e))

    @patch.object(requests.Session, 'request')
    def test_get_access_token_grant_type(self, mock_request):
        mock_request.return_value = self.response
        data = dict(code='4242', grant_type='refresh_token')
        response = \
            self.service.get_access_token(data=data).content
        self.assertEqual(response['access_token'], '321')

    @patch.object(requests.Session, 'request')
    def test_request(self, mock_request):
        self.response.content = json.dumps({'status': 'ok'})
        self.response.headers['content-type'] = 'json'
        mock_request.return_value = self.response
        response = self.service.request('GET',
                                        'http://example.com/endpoint',
                                         access_token='321').content
        self.assertEqual(response['status'], 'ok')

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

        with self.assertRaises(Exception) as e:
            self.service.request('GET',
                                 'http://example.com/endpoint',
                                  access_token='321')
            self.assertEqual('Response not OK!', str(e))


class OAuth1ServiceTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp(self)

        # mock service for testing
        service = OAuth1Service(
                'example',
                consumer_key='123',
                consumer_secret='456',
                request_token_url='http://example.com/request_token',
                access_token_url='http://example.com/access_token',
                authorize_url='http://example.com/authorize')
        self.service = service

        # mock response content
        self.response.content = 'oauth_token=123&oauth_token_secret=456'

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

        response = self.service.get_request_token('GET')
        self.assertEqual(response, 'Oops, something went wrong :(')

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

        response = \
            self.service.request('GET',
                                 'http://example.com/some/method',
                                 access_token='123',
                                 access_token_secret='456').content
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
