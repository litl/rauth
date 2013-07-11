# -*- coding: utf-8 -*-
'''
    rauth.test_session
    ------------------

    Test suite for rauth.session.
'''

from base import RauthTestCase
from rauth.session import OAuth1Session, OAuth2Session, OflySession

from mock import patch

import requests

import json


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
    def test_request_with_optional_params_without_data(self, mock_request):
        mock_request.return_value = self.response
        r = self.session.request('POST', 'http://example.com/')
        self.assert_ok(r)

    @patch.object(requests.Session, 'request')
    def test_request_with_header_auth(self, mock_request):
        mock_request.return_value = self.response
        r = self.session.request('GET',
                                 'http://example.com/',
                                 header_auth=True)
        self.assert_ok(r)

    def test_headers_case_insensitive(self):
        def start_test_server():
            from wsgiref.util import setup_testing_defaults
            from wsgiref.headers import Headers
            from wsgiref.simple_server import make_server
            from threading import Thread

            def test_server(environ, start_response):
                setup_testing_defaults(environ)

                status = '200 OK'
                headers = [('Content-type', 'text/plain')]

                start_response(status, headers)

                env = [(str(key), str(value))
                       for key, value in environ.iteritems()]

                ret = json.dumps(dict(env))

                return ret

            def create_server():
                httpd = make_server('', 8000, test_server)
                httpd.serve_forever()

            t = Thread(target=create_server)
            t.setDaemon(True)
            t.start()

        start_test_server()

        # case 1 (case-insensitive)
        headers = {
            'aUtHoRiZaTiOn': 'foobar'  # Authorization
        }
        r = self.session.request('GET',
                                 'http://127.0.0.1:8000/',
                                 headers=headers,
                                 header_auth=True,
                             )

        self.assertEqual(r.status_code, 200)
        data = json.loads(r.content)
        self.assertEqual(data['CONTENT_TYPE'], 'text/plain')
        self.assertNotIn(data['HTTP_AUTHORIZATION'], 'foobar')

        # case 2 (case-insensitive)
        headers = {
            'contenT-typE': 'text/html',
        }
        r = self.session.request('GET',
                                 'http://127.0.0.1:8000/',
                                 headers=headers,
                                 header_auth=True,
                             )

        self.assertEqual(r.status_code, 200)
        data = json.loads(r.content)
        self.assertNotEqual(data['CONTENT_TYPE'], 'text/plain')
        self.assertEqual(data['CONTENT_TYPE'], 'text/html')

        # case 3 (#67)
        headers = {
            'content-type': 'application/json',
        }

        payload = {
            'test': 'me'
        }

        r = self.session.request('POST',
                                 'http://127.0.0.1:8000/',
                                 headers=headers,
                                 header_auth=True,
                                 data=payload,
                             )

        self.assertEqual(r.status_code, 200)
        data = json.loads(r.content)
        self.assertEqual(data['CONTENT_TYPE'], 'application/json')


class OAuth2SessionTestCase(RauthTestCase, RequestMixin):
    def setUp(self):
        RauthTestCase.setUp(self)

        self.session = OAuth2Session('123', '345')


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
