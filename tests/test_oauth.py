# -*- coding: utf-8 -*-
'''
    rauth.test_oauth
    ------------------

    Test suite for rauth.oauth.
'''

from base import RauthTestCase
from rauth.oauth import (HmacSha1Signature, RsaSha1Signature,
                         PlaintextSignature)
from rauth.utils import FORM_URLENCODED

from urllib import urlencode


class OAuthTestHmacSha1Case(RauthTestCase):
    def get_req_kwargs(self, req_kwargs):
        req_kwargs.setdefault('headers', {})
        p = req_kwargs.get('params', {})
        d = req_kwargs.get('data', {})

        req_kwargs['headers'].update({'x-rauth-root-url':
                                      'http://example.com/'})

        req_kwargs['headers'].update({'x-rauth-params-data': (p, d)})

        return req_kwargs

    def test_hmacsha1_signature(self):
        req_kwargs = self.get_req_kwargs({'params': {'foo': 'bar'}})

        oauth_signature = HmacSha1Signature().sign(self.oauth1session,
                                                   'GET',
                                                   req_kwargs)
        self.assertIsNotNone(oauth_signature)
        self.assertTrue(isinstance(oauth_signature, str))
        self.assertEqual(oauth_signature, 'cYzjVXCOk62KoYmJ+iCvcAcgfp8=')

    def test_normalize_request_parameters_params(self):
        # params as a dict
        req_kwargs = self.get_req_kwargs({'params': {'foo': 'bar'}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo=bar',  normalized)

        # params as a dict with URL encodable chars
        self.oauth1session.oauth_params = {}
        req_kwargs = self.get_req_kwargs({'params': {'foo+bar': 'baz'}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo%2Bbar=baz',  normalized)
        self.assertNotIn('+', normalized)

        # params as a string
        self.oauth1session.oauth_params = {}
        req_kwargs = self.get_req_kwargs({'params': urlencode({'foo': 'bar'})})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo=bar',  normalized)

        # params as a string with URL encodable chars
        self.oauth1session.oauth_params = {}
        req_kwargs = self.get_req_kwargs({'params':
                                          urlencode({'foo+bar': 'baz'})})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo%2Bbar=baz',  normalized)
        self.assertNotIn('+', normalized)

        # params and dict as dicts
        self.oauth1session.oauth_params = {}
        req_kwargs = self.get_req_kwargs({'params': {'a': 'b'},
                                          'data': {'foo': 'bar'},
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('a=b&foo=bar',  normalized)

    def test_normalize_request_parameters_data(self):
        # data as a dict
        req_kwargs = self.get_req_kwargs({'data': {'foo': 'bar'},
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo=bar',  normalized)

        # data as a dict with URL encodable chars
        self.oauth1session.oauth_params = {}
        req_kwargs = self.get_req_kwargs({'data': {'foo+bar': 'baz'},
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo%2Bbar=baz',  normalized)
        self.assertNotIn('+', normalized)

        # data as a string with URL encodable chars
        self.oauth1session.oauth_params = {}
        data = urlencode({'foo+bar': 'baz'})
        req_kwargs = self.get_req_kwargs({'data': data,
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo%2Bbar=baz',  normalized)
        self.assertNotIn('+', normalized)

    def test_normalize_request_parameters_both_string(self):
        # params and data both as a string
        req_kwargs = self.get_req_kwargs({'params': urlencode({'a': 'b'}),
                                          'data': urlencode({'foo': 'bar'}),
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)

        # this also demonstrates sorting
        self.assertEqual('a=b&foo=bar',  normalized)

    def test_normalize_request_parameters_params_string(self):
        # params is a string but data is a dict
        req_kwargs = self.get_req_kwargs({'params': urlencode({'a': 'b'}),
                                          'data': {'foo': 'bar'},
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('a=b&foo=bar',  normalized)

    def test_normalize_request_parameters_data_string(self):
        # params is a dict but data is a string
        req_kwargs = self.get_req_kwargs({'params': {'a': 'b'},
                                          'data': urlencode({'foo': 'bar'}),
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)

        self.assertEqual('a=b&foo=bar',  normalized)

    def test_normalize_request_parameters_whitespace(self):
        req_kwargs = self.get_req_kwargs({'data': {'foo': 'bar baz'},
                                          'headers': {'Content-Type':
                                                      FORM_URLENCODED}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('foo=bar%20baz', normalized)

    def test_utf8_encoded_string(self):
        # in the event a string is already UTF-8
        req_kwargs = self.get_req_kwargs({'params': {u'foo': u'bar'}})
        method = u'GET'
        sig = HmacSha1Signature().sign(self.oauth1session,
                                       method,
                                       req_kwargs)
        self.assertEqual('cYzjVXCOk62KoYmJ+iCvcAcgfp8=',  sig)

    def test_x_rauth_params_data_p_without_params(self):
        p = {'params': {u'foo': u'bar'}}
        d = {}
        req_kwargs = {'headers': {'x-rauth-root-url': 'http://example.com/',
                                  'x-rauth-params-data': (p, d)}}
        method = u'GET'
        sig = HmacSha1Signature().sign(self.oauth1session,
                                       method,
                                       req_kwargs)
        self.assertEqual('4i9nEmEn4yyocpSHw/Od7cYAEGM=',  sig)

    def test_x_rauth_params_data_d_without_data(self):
        p = {}
        d = {'data': {u'foo': u'bar'}}
        req_kwargs = {'headers': {'x-rauth-root-url': 'http://example.com/',
                                  'x-rauth-params-data': (p, d)}}
        method = u'GET'
        sig = HmacSha1Signature().sign(self.oauth1session,
                                       method,
                                       req_kwargs)
        self.assertEqual('wEF9KljihRCPgmMNvMwrvjJBuqY=',  sig)

    def test_remove_query_string(self):
        # can't sign the URL with the query string so
        url = 'http://example.com/?foo=bar'
        signable_url = HmacSha1Signature()._remove_qs(url)
        self.assertEqual('http://example.com/', signable_url)

    def test_normalize_request_parameters_data_not_urlencoded(self):
        # not sending the 'application/x-www-form-urlencoded' header
        # therefore the data will not be included in the signature
        self.oauth1session.oauth_params = {}
        req_kwargs = self.get_req_kwargs({'data': {'foo': 'bar'}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('',  normalized)

        self.oauth1session.oauth_params = {}
        req_kwargs = self.get_req_kwargs({'params': {'a': 'b'},
                                          'data': {'foo': 'bar'}})
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth1session, req_kwargs)
        self.assertEqual('a=b',  normalized)


class OAuthTestRsaSha1Case(RauthTestCase):
    def test_rsasha1_notimplemented(self):
        self.assertRaises(NotImplementedError, RsaSha1Signature)


class OAuthTestPlaintextCase(RauthTestCase):
    def test_plaintext_notimplemented(self):
        self.assertRaises(NotImplementedError, PlaintextSignature)
