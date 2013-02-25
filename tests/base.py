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

from inspect import stack, isfunction

from mock import Mock
from nose.tools import nottest


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


def _new_func(func_name, func, f):
    def decorated(cls):
        return func(cls, f)
    decorated.__name__ = func_name
    return decorated


def parameterize(inp):
    '''
    Based on nose-parameterized, distilled for "brute force" usage. Also
    modified to display more informative function names, i.e. actual input.
    Useful for debugging purposes.
    '''
    def decorated(func):
        frame = stack()[1]
        frame_locals = frame[0].f_locals

        base_name = func.__name__
        for i, f in enumerate(inp):
            if not isfunction(f):
                raise TypeError('Arguments should be wrapped in a function.')
            name_suffix = ' --> ' + '(' + str(f.__args__) + ')'
            name = base_name + name_suffix
            new_func = _new_func(name, func, f)
            frame_locals[name] = new_func
        return nottest(func)
    return decorated
