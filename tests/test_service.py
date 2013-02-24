# -*- coding: utf-8 -*-
'''
    rauth.test_service
    ------------------

    Test suite for rauth.service.
'''

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
        r = self.service.get(self.http_url)
        self.assert_ok(r)

    def test_options(self):
        r = self.service.options(self.http_url)
        self.assert_ok(r)

    def test_head(self):
        r = self.service.head(self.http_url)
        self.assert_ok(r)

    def test_post(self):
        r = self.service.post(self.http_url)
        self.assert_ok(r)

    def test_put(self):
        r = self.service.put(self.http_url)
        self.assert_ok(r)

    def test_patch(self):
        r = self.service.patch(self.http_url)
        self.assert_ok(r)

    def test_delete(self):
        r = self.service.delete(self.http_url)
        self.assert_ok(r)


def get_input_combos():
    all_params = [{},
                  {'foo': 'bar'},
                  'foo=bar',
                  {u'foo': u'bar'},
                  u'foo=bar',
                  'føø=bår',
                  {'føø': 'bår'},
                  {u'føø': u'bår'},
                  'foo=bar baz',
                  {'foo': 'bar baz'}]
    all_data = [{},
                {'foo': 'bar'},
                'foo=bar',
                {u'foo': u'bar'},
                u'foo=bar',
                'føø=bår',
                {'føø': 'bår'},
                {u'føø': u'bår'},
                'foo=bar baz',
                {'foo': 'bar baz'}]
    all_headers = [{},
                   {'x-foo-bar': 'baz'},
                   {u'x-foo-bar': u'baz'},
                   {'x-foo-bar': 'båz'},
                   {u'x-foo-bar': u'båz'},
                   {'x-foo-bar': 'baz foo'}]

    input_combos = []
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
                input_combos.append((method, kwargs))
    return input_combos
