'''
    rauth.test_hook
    ---------------

    Test suite for rauth.hook.
'''

import unittest

if not hasattr(unittest.TestCase, 'assertIsNotNone'):
    import unittest2 as unittest

from mock import Mock
from requests import Request


class RauthTestCase(unittest.TestCase):
    def setUp(self):
        # mock request object
        request = Request()
        request.method = 'GET'
        request.url = 'http://example.com/'
        request.params = {}
        request.data = {}
        request.params_and_data = {}
        self.request = request

        # mock response object
        response = Mock()
        response.content = 'access_token=321'
        response.headers = {'content-type': 'text/html; charset=UTF-8'}
        response.ok = True
        response.status_code = 200
        self.response = response

        # mock raise_for_status with an error
        def raise_for_status():
            raise Exception('Response not OK!')

        self.raise_for_status = raise_for_status

        # mock hook object
        hook = Mock()
        hook.consumer_key = '123'
        hook.consumer_secret = '456'
        hook.access_token = '321'
        hook.access_token_secret = '654'
        self.hook = hook
