# -*- coding: utf-8 -*-
'''
    rauth.test_service_ofly
    -----------------------

    Test suite for rauth.service.OflyService.
'''

from base import RauthTestCase
from test_service import (FakeHexdigest, HttpMixin, MutableDatetime,
                          RequestMixin)

from rauth.service import OflyService, Service
from rauth.session import OFLY_DEFAULT_TIMEOUT, OflySession

from copy import deepcopy
from datetime import datetime
from functools import wraps
from urlparse import parse_qsl, urlsplit

from mock import patch

import requests


class OflyServiceTestCase(RauthTestCase, RequestMixin, HttpMixin):
    app_id = '000'
    user_id = '123'

    def setUp(self):
        RauthTestCase.setUp(self)

        self.authorize_url = 'http://example.com/authorize'
        self.base_url = 'http://example.com/api/'

        self.service = OflyService(self.app_id,
                                   '111',
                                   name='service',
                                   authorize_url=self.authorize_url,
                                   base_url=self.base_url)

        self.service.request = self.fake_request
        self.service.user_id = self.user_id

    def fake_get_sorted_params(self, params):
        def sorting_gen():
            for k in sorted(params.keys()):
                yield '='.join((k, params[k]))
        return '&'.join(sorting_gen())

    def fake_sign(app_id, user_id):
        def wrap(func):
            @wraps(func)
            @patch('rauth.session.datetime', MutableDatetime)
            @patch('rauth.session.md5', FakeHexdigest)
            @patch('rauth.session.sha1', FakeHexdigest)
            def decorated(*args, **kwargs):
                hash_meth = kwargs.get('hash_meth', 'sha1').upper()
                ofly_params = {'oflyAppId': app_id,
                               'oflyHashMeth': hash_meth,
                               'oflyTimestamp': '1900-01-01T00:00:00.0Z',
                               'oflyApiSig': 'foo',
                               'oflyUserid': user_id}

                MutableDatetime.utcnow = \
                    classmethod(lambda cls: datetime(1900, 1, 1))
                return func(ofly_params=ofly_params, *args, **kwargs)
            return decorated
        return wrap

    @patch.object(requests.Session, 'request')
    @fake_sign(app_id, user_id)
    def fake_request(self,
                     method,
                     url,
                     mock_request,
                     ofly_params,
                     user_id=None,
                     hash_meth='sha1',
                     **kwargs):
        mock_request.return_value = self.response

        user_id = user_id or self.service.user_id

        session = self.service.get_session(user_id)
        service = Service('service',
                          self.service.base_url,
                          self.service.authorize_url)

        r = service.request(session,
                            method,
                            url,
                            user_id=user_id,
                            hash_meth=hash_meth,
                            **deepcopy(kwargs))

        url = service._set_url(url)

        kwargs.setdefault('params', {})
        if isinstance(kwargs['params'], basestring):
            kwargs['params'] = dict(parse_qsl(kwargs['params']))

        url_path = urlsplit(url).path

        signature_base_string = self.service.app_secret + url_path + '?'

        if len(kwargs['params']):
            signature_base_string += \
                self.fake_get_sorted_params(kwargs['params']) + '&'

        signature_base_string += self.fake_get_sorted_params(ofly_params)

        _all_params = dict(ofly_params.items() + kwargs['params'].items())

        kwargs['params'] = self.fake_get_sorted_params(_all_params)

        mock_request.assert_called_with(method,
                                        url,
                                        timeout=OFLY_DEFAULT_TIMEOUT,
                                        **kwargs)
        return r

    def test_get_session(self):
        s1 = self.service.get_session('foo')
        s2 = self.service.get_session('foo')
        self.assertIsInstance(s1, OflySession)
        self.assertIs(s1, s2)

    @fake_sign(app_id, user_id)
    def test_get_authorize_url(self, ofly_params):
        expected_url = 'http://example.com/authorize?'
        ofly_params.pop('oflyUserid')
        params = self.fake_get_sorted_params(ofly_params)
        url = self.service.get_authorize_url()
        self.assertEqual(url, expected_url + params)

    def test_request_with_md5(self):
        r = self.service.request('GET',
                                 'http://example.com/',
                                 user_id=self.user_id,
                                 hash_meth='md5')
        self.assert_ok(r)

    def test_request_with_bad_hash_meth(self):
        with self.assertRaises(TypeError) as e:
            self.service.request('GET',
                                 'http://example.com/',
                                 user_id=self.user_id,
                                 hash_meth='foo')
        self.assertEqual(str(e.exception),
                         'hash_meth must be one of "sha1", "md5"')

    def test_request_with_nonetype_user_id(self):
        self.service.user_id = None
        with self.assertRaises(AssertionError) as e:
            self.service.request('GET', 'http://example.com/')
        self.assertEqual(str(e.exception),
                         'An oflyUserid must be provided as `user_id`.')
