'''
    webauth.test_hook
    -----------------

    Test suite for webauth.hook.
'''

import unittest

from mock import Mock
from requests import Request


class WebauthTestCase(unittest.TestCase):
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
