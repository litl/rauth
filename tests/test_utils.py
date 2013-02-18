# -*- coding: utf-8 -*-
'''
    rauth.test_utils
    ----------------

    Test suite for rauth.utils.
'''

from base import RauthTestCase
from rauth.utils import absolute_url, parse_utf8_qsl


class UtilsTestCase(RauthTestCase):
    def test_absolute_url(self):
        self.assertTrue(absolute_url('http://example.com/'))

    def test_absolute_url_https(self):
        self.assertTrue(absolute_url('https://example.com/'))

    def test_not_absolute_url(self):
        self.assertFalse(absolute_url('/some/resource'))

    def test_parse_utf8_qsl(self):
        d = parse_utf8_qsl('fü=bar&rauth=über')
        self.assertEqual(d, {u'rauth': u'\xfcber', u'f\xfc': u'bar'})
