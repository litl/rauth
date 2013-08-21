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

# HACK: give a more informative error message if we're missing deps here
try:
    from Crypto.PublicKey import RSA
except ImportError:
    raise RuntimeError('PyCrypto is required to run the rauth test suite')

try:
    stringtype = unicode  # python 2
except NameError:
    stringtype = str  # python 3

assert RSA


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
        self.assertIsInstance(oauth_signature, stringtype)
        self.assertEqual(oauth_signature, 'cYzjVXCOk62KoYmJ+iCvcAcgfp8=')

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
        self.assertEqual('cYzjVXCOk62KoYmJ+iCvcAcgfp8=',  sig)

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
        self.assertEqual('JzmJUmqjdNYBJsJWbtQKXnc0W8w=',  sig)

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
    private_key = '''-----BEGIN RSA PRIVATE KEY-----
        MIICXQIBAAKBgQDf0jdU+07T1B9erQBNS46JmvO7vsNfdNXkoEx4UwLwqsmv1wKs
        RvCXBVyNYnnHYVQjSDRgyviNLYSP01DXqmwKlhSN9sbjiCeswXlG2B4BdFdO687J
        9ZOmeyZsb6OFlXWediqkfvDaArSPM884YB2A8rqJd2y8Hd4tSG2Ns2o7WwIDAQAB
        AoGBAMJ8FO54LMfuU4/d/hwsImA5z759BaGFkXLHQ4tufmiHzxdHWqA+SELCOujz
        /+ObFBRQYosU86MhQUYElgPAp31u6MfmNc7nPvtuy1rSYVYD05oUqeyKBCycZa9r
        F9+5ASNdvYF/vvAj5gQ2aOZPGsTf80hrUIDt2ebJn1yq3R1BAkEA49qUpQbKHDdJ
        I9CZiiptySClyxyR3++oPw1UR9vfTz0qkzExYeS59TROX+sVpcpp/LFeTV8HeDVl
        nUEv3xtEYQJBAPt4HDw21gRqL0W3V7xQIrCBnzttBA83y3hUpn1wRelJnnVsAUwv
        KtxFZPSTprDFf3eTJP5vWEYcM4CME7L0GTsCQDAg1HMDOx+4oc9Z2YSwr53jMoHz
        l/B4O86Nrza6f7HKFrsekfK+kHT1xnRGQL1TQw3oHSY0o2xFwx/zS/xRUyECQQDA
        k/ojjucVWHA9Vqwk9cWrIIleDB2YveTfkQwzciDICG4GhKD1xAVxzN8EgnKcW5ND
        cndZNtIGVyCF6EBJwq/zAkBjcXFUJMXXYiIzIpKJD2ZEMms2PXBkB0OxG+Yr0r4G
        /w3QafaS0cyRCu0z0fY52+wcn5VrHk97sLQhLMQv07ij
        -----END RSA PRIVATE KEY-----'''
    method = 'GET'
    url = 'http://example.com/'
    oauth_params = {}
    req_kwargs = {'params': {'foo': 'bar'}}

    def test_rsasha1_signature(self):
        oauth_signature = RsaSha1Signature().sign(self.private_key,
                                                  None,
                                                  self.method,
                                                  self.url,
                                                  self.oauth_params,
                                                  self.req_kwargs)
        self.assertIsNotNone(oauth_signature)
        self.assertIsInstance(oauth_signature, stringtype)
        self.assertEqual(oauth_signature,
                         'MEnbOKBw0lWi5NvGyrABQ6tPygWiNOjGz47y8d+SQfXYrzsvK'
                         'kzcMgt2VGBRgKsKSdFho36TuCuP75Qe1uou6/rhHrZoSppQ+6'
                         'vdPSKkriGzSK3azqBacg9ZIIVy/atHPTm6BAvo+0v4ysiI9ci'
                         '7hJbRkXL0NJVz/p0ZQKO/Jds=')

    def test_rsasha1_badargument(self):
        self.assertRaises(ValueError, RsaSha1Signature().sign,
                          None, None,
                          self.method,
                          self.url,
                          self.oauth_params,
                          self.req_kwargs)


class OAuthTestPlaintextCase(RauthTestCase):
    def test_plaintext_notimplemented(self):
        self.assertRaises(NotImplementedError, PlaintextSignature)
