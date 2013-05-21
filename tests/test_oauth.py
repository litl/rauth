# -*- coding: utf-8 -*-
'''
    rauth.test_oauth
    ------------------

    Test suite for rauth.oauth.
'''

from base import RauthTestCase
from rauth.compat import str
from rauth.oauth import (HmacSha1Signature, RsaSha1Signature,
                         PlaintextSignature)
from rauth.utils import FORM_URLENCODED


class OAuthTestHmacSha1Case(RauthTestCase):
    consumer_secret = '456'
    access_token_secret = '654'
    method = 'GET'
    url = 'http://example.com/'
    oauth_params = {}
    req_kwargs = {'params': {'foo': 'bar'}}

    def test_hmacsha1_signature(self):
        oauth_signature = HmacSha1Signature().sign(self.consumer_secret,
                                                   self.access_token_secret,
                                                   self.method,
                                                   self.url,
                                                   self.oauth_params,
                                                   self.req_kwargs)
        self.assertIsNotNone(oauth_signature)
        self.assertIsInstance(oauth_signature, str)
        self.assertEqual(oauth_signature, u'cYzjVXCOk62KoYmJ+iCvcAcgfp8=')

    def test_normalize_request_parameters_params(self):
        # params as a dict
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth_params, self.req_kwargs)
        self.assertEqual('foo=bar',  normalized)

        # params as a dict with URL encodable chars
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth_params,
                                           {'params': {'foo+bar': 'baz'}})
        self.assertEqual('foo%2Bbar=baz',  normalized)
        self.assertNotIn('+', normalized)

        # params and dict as dicts
        req_kwargs = {'params': {'a': 'b'},
                      'data': {'foo': 'bar'},
                      'headers': {'Content-Type': FORM_URLENCODED}}

        normalized = HmacSha1Signature()\
            ._normalize_request_parameters({}, req_kwargs)
        self.assertEqual('a=b&foo=bar',  normalized)

    def test_normalize_request_parameters_data(self):
        # data as a dict
        req_kwargs = {'data': {'foo': 'bar'},
                      'headers': {'Content-Type': FORM_URLENCODED}}
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth_params, req_kwargs)
        self.assertEqual('foo=bar',  normalized)

        # data as a dict with URL encodable chars
        req_kwargs = {'data': {'foo+bar': 'baz'},
                      'headers': {'Content-Type': FORM_URLENCODED}}
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters({}, req_kwargs)
        self.assertEqual('foo%2Bbar=baz',  normalized)
        self.assertNotIn('+', normalized)

        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth_params, req_kwargs)
        self.assertEqual('foo%2Bbar=baz',  normalized)
        self.assertNotIn('+', normalized)

    def test_normalize_request_parameters_whitespace(self):
        req_kwargs = {'data': {'foo': 'bar baz'},
                      'headers': {'Content-Type': FORM_URLENCODED}}
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth_params, req_kwargs)
        self.assertEqual('foo=bar%20baz', normalized)

    def test_sign_utf8_encoded_string(self):
        # in the event a string is already UTF-8
        req_kwargs = {u'params': {u'foo': u'bar'}}
        sig = HmacSha1Signature().sign(self.consumer_secret,
                                       self.access_token_secret,
                                       u'GET',
                                       self.url,
                                       self.oauth_params,
                                       req_kwargs)
        self.assertEqual(u'cYzjVXCOk62KoYmJ+iCvcAcgfp8=',  sig)

    def test_sign_with_data(self):
        # in the event a string is already UTF-8
        req_kwargs = {'data': {'foo': 'bar'}}
        method = 'POST'
        sig = HmacSha1Signature().sign(self.consumer_secret,
                                       self.access_token_secret,
                                       method,
                                       self.url,
                                       self.oauth_params,
                                       req_kwargs)
        self.assertEqual(u'JzmJUmqjdNYBJsJWbtQKXnc0W8w=',  sig)

    def test_remove_query_string(self):
        # can't sign the URL with the query string so
        url = 'http://example.com/?foo=bar'
        signable_url = HmacSha1Signature()._remove_qs(url)
        self.assertEqual('http://example.com/', signable_url)

    def test_normalize_request_parameters_data_not_urlencoded(self):
        # not sending the 'application/x-www-form-urlencoded' header
        # therefore the data will not be included in the signature
        req_kwargs = {'data': {'foo': 'bar'}}
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters(self.oauth_params, req_kwargs)
        self.assertEqual('',  normalized)

        req_kwargs = {'params': {'a': 'b'}, 'data': {'foo': 'bar'}}
        normalized = HmacSha1Signature()\
            ._normalize_request_parameters({}, req_kwargs)
        self.assertEqual('a=b',  normalized)


class OAuthTestRsaSha1Case(RauthTestCase):
    def test_rsasha1_notimplemented(self):
        self.assertRaises(NotImplementedError, RsaSha1Signature)


class OAuthTestPlaintextCase(RauthTestCase):
    def test_plaintext_notimplemented(self):
        self.assertRaises(NotImplementedError, PlaintextSignature)
