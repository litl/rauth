# -*- coding: utf-8 -*-
'''
    rauth.base
    ----------

    Test suite common infrastructure.
'''

import json

import requests
import unittest

if not hasattr(unittest.TestCase, 'assertIsNotNone'):
    try:
        import unittest2 as unittest
    except ImportError:
        raise Exception('unittest2 is required to run the rauth test suite')

from mock import Mock


class RauthTestCase(unittest.TestCase):
    def setUp(self):
        response = Mock()
        response.content = json.dumps({'status': 'ok'})
        response.headers = {'Content-Type': 'application/json'}
        response.ok = True
        response.status_code = requests.codes.ok
        self.response = response

        # mock session objects
        oauth1session = Mock()
        oauth1session.oauth_params = {}
        oauth1session.consumer_key = '123'
        oauth1session.consumer_secret = '456'
        oauth1session.access_token = '321'
        oauth1session.access_token_secret = '654'
        self.oauth1session = oauth1session
