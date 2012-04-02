'''
    rauth.test_hook
    ---------------

    Test suite for rauth.hook.
'''

import unittest

from mock import Mock
from requests import Request


class RauthTestCase(unittest.TestCase):
    def setUp(self):
        # mock request object
        request = Request()
        request.method = 'GET'
        request.url = 'http://example.com/'
        request.headers = {}
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
        response.raise_for_status = lambda: None
        self.response = response

        # mock raise_for_status with an error
        def raise_for_status():
            raise Exception('Response not OK!')

        self.raise_for_status = raise_for_status

        # mock consumer object
        consumer = Mock()
        consumer.key = '123'
        consumer.secret = '456'
        self.consumer = consumer

        # mock token object
        token = Mock()
        token.key = '321'
        token.secret = '456'
        self.token = token
