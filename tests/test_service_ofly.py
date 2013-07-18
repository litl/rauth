# -*- coding: utf-8 -*-
'''
    rauth.test_service_ofly
    -----------------------

    Test suite for rauth.service.OflyService.
'''

from base import RauthTestCase
from test_service import (FakeHexdigest, HttpMixin, MutableDatetime,
                          RequestMixin, ServiceMixin)

from rauth.compat import parse_qsl, urlsplit, is_basestring
from rauth.service import OflyService
from rauth.session import OFLY_DEFAULT_TIMEOUT, OflySession

from copy import deepcopy
from datetime import datetime
from functools import wraps

from mock import patch

import requests

import pickle


class OflyServiceTestCase(RauthTestCase, RequestMixin, ServiceMixin,
                          HttpMixin):
    app_id = '000'
    app_secret = '111'

    user_id = '123'

    def setUp(self):
        RauthTestCase.setUp(self)

        self.authorize_url = 'http://example.com/authorize'
        self.base_url = 'http://example.com/api/'

        self.service = OflyService(self.app_id,
                                   self.app_secret,
                                   name='service',
                                   authorize_url=self.authorize_url,
                                   base_url=self.base_url)

        self.session = self.service.get_session(self.user_id)

        # patch
        self.session.request = self.fake_request
        self.service.get_session = self.fake_get_session

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

        service = OflyService(self.app_id,
                              self.app_secret,
                              name='service',
                              authorize_url=self.authorize_url,
                              base_url=self.base_url)

        session = service.get_session(self.user_id)

        r = session.request(method,
                            url,
                            user_id=user_id,
                            hash_meth=hash_meth,
                            **deepcopy(kwargs))

        url = self.session._set_url(url)

        kwargs.setdefault('params', {})
        if is_basestring(kwargs['params']):
            kwargs['params'] = dict(parse_qsl(kwargs['params']))

        url_path = urlsplit(url).path

        signature_base_string = self.service.app_secret + url_path + '?'

        if len(kwargs['params']):
            signature_base_string += \
                self.fake_get_sorted_params(kwargs['params']) + '&'

        signature_base_string += self.fake_get_sorted_params(ofly_params)

        all_params = dict(tuple(ofly_params.items())
                          + tuple(kwargs['params'].items()))

        kwargs['params'] = self.fake_get_sorted_params(all_params)
        if not isinstance(kwargs['params'], bytes):
            kwargs['params'] = kwargs['params'].encode('utf-8')

        mock_request.assert_called_with(method,
                                        url,
                                        timeout=OFLY_DEFAULT_TIMEOUT,
                                        **kwargs)
        return r

    def fake_get_session(self, token):
        return self.session

    def test_get_session(self):
        s = self.service.get_session('foo')
        self.assertIsInstance(s, OflySession)

    @fake_sign(app_id, user_id)
    def test_get_authorize_url(self, ofly_params):
        expected_url = 'http://example.com/authorize?'
        ofly_params.pop('oflyUserid')
        params = self.fake_get_sorted_params(ofly_params)
        url = self.service.get_authorize_url()
        self.assertEqual(url, expected_url + params)

    def test_request_with_md5(self):
        r = self.session.request('GET',
                                 'http://example.com/',
                                 user_id=self.user_id,
                                 hash_meth='md5')
        self.assert_ok(r)

    def test_request_with_bad_hash_meth(self):
        with self.assertRaises(TypeError) as e:
            self.session.request('GET',
                                 'http://example.com/',
                                 user_id=self.user_id,
                                 hash_meth='foo')
        self.assertEqual(str(e.exception),
                         'hash_meth must be one of "sha1", "md5"')

    def test_get_auth_session(self):
        s = self.service.get_auth_session('foo')
        self.assertIsInstance(s, OflySession)

    def test_pickle_session(self):
        session = pickle.loads(pickle.dumps(self.session))

        # Add the fake request back to the session
        session.request = self.fake_request
        r = self.session.request('GET',
                                 'http://example.com/',
                                 user_id=self.user_id,
                                 hash_meth='md5')
        self.assert_ok(r)
