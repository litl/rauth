# -*- coding: utf-8 -*-
'''
    rauth.test_service
    ------------------

    Test suite for rauth.service.
'''

from base import parameterize

from copy import deepcopy
from datetime import datetime

import json


class MutableDatetime(datetime):
    def __new__(cls, *args, **kwargs):
        return datetime.__new__(datetime, *args, **kwargs)


class FakeHexdigest(object):
    def __init__(self, *args):
        pass

    def hexdigest(self):
        return 'foo'


class HttpMixin(object):
    http_url = 'http://example.com/'

    def assert_ok(self, r):
        self.assertEqual(json.loads(r.content), {'status': 'ok'})

    def test_get(self):
        r = self.session.get(self.http_url)
        self.assert_ok(r)

    def test_options(self):
        r = self.session.options(self.http_url)
        self.assert_ok(r)

    def test_head(self):
        r = self.session.head(self.http_url)
        self.assert_ok(r)

    def test_post(self):
        r = self.session.post(self.http_url)
        self.assert_ok(r)

    def test_put(self):
        r = self.session.put(self.http_url)
        self.assert_ok(r)

    def test_patch(self):
        r = self.session.patch(self.http_url)
        self.assert_ok(r)

    def test_delete(self):
        r = self.session.delete(self.http_url)
        self.assert_ok(r)


def input_product_gen():
    all_params = [{},
                  '',
                  {'foo': 'bar'},
                  {'foo': 'bar baz'},
                  {'foo': 'bar=baz&a=b'},
                  {u'foo': u'bar'},
                  {'føø': 'bår'},
                  {u'føø': u'bår'},
                  'foo=bar',
                  'foo=bar baz',
                  'foo=bar&a=b',
                  u'foo=bar',
                  'føø=bår',
                  u'føø=bår']

    all_data = deepcopy(all_params)

    all_headers = [{},
                   {'x-foo-bar': 'baz'},
                   {u'x-foo-bar': u'baz'},
                   {'x-foo-bar': 'båz'},
                   {u'x-foo-bar': u'båz'},
                   {'x-foo-bar': 'baz foo'},
                   {u'x-foo-bar': u'baz foo'},
                   {'x-foo-bar': 'båz foo'},
                   {u'x-foo-bar': u'båz foo'},
                   {'Content-Type': 'application/x-www-form-urlencoded'},
                   {'Content-Type': 'application/json'}]

    for p in all_params:
        method = 'GET'
        for d in all_data:
            if d:
                method = 'POST'
            for h in all_headers:
                kwargs = {}

                kwargs['params'] = p
                kwargs['data'] = d
                kwargs['headers'] = h

                yield lambda m=method, k=kwargs: (m, k)


class RequestMixin(object):
    @parameterize(input_product_gen())
    def test_request(self, method, kwargs):
        r = self.session.request(method, 'foo', **kwargs)
        self.assert_ok(r)
