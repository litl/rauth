# -*- coding: utf-8 -*-
'''
    rauth.test_utils
    ----------------

    Test suite for rauth.utils.
'''

from base import RauthTestCase
from rauth.utils import absolute_url, CaseInsensitiveDict, parse_utf8_qsl


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

    def test_both_kv_unicode(self):
        d = parse_utf8_qsl(u'fü=bar&rauth=über')
        self.assertEqual(d, {u'rauth': u'\xfcber', u'f\xfc': u'bar'})

    def test_rauth_case_insensitive_dict(self):
        d = CaseInsensitiveDict()
        d.setdefault('Content-Type', 'foo')

        d.update({'content-type': 'bar'})

        self.assertEqual(1, len(d.keys()))
        self.assertIn('content-type', d.keys())
        self.assertEqual({'content-type': 'bar'}, d)

        d.update({'CONTENT-TYPE': 'baz'})

        self.assertEqual(1, len(d.keys()))
        self.assertIn('content-type', d.keys())
        self.assertEqual({'content-type': 'baz'}, d)

    def test_rauth_case_insensitive_dict_list_of_tuples(self):
        d = CaseInsensitiveDict([('Content-Type', 'foo')])
        self.assertEqual(d, {'content-type': 'foo'})
