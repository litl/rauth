# -*- coding: utf-8 -*-
'''
    rauth.base
    ----------

    Test suite common infrastructure.
'''

import unittest

if not hasattr(unittest.TestCase, 'assertIsNotNone'):
    try:
        import unittest2 as unittest
    except ImportError:
        raise Exception('unittest2 is required to run the rauth test suite')

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

        # mock session objects
        oauth1session = Mock()
        oauth1session.oauth_params = {}
        oauth1session.consumer_key = '123'
        oauth1session.consumer_secret = '456'
        oauth1session.access_token = '321'
        oauth1session.access_token_secret = '654'
        self.oauth1session = oauth1session
