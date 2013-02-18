# -*- coding: utf-8 -*-
'''
    rauth.utils
    -----------

    General utilities.
'''

from urlparse import parse_qsl

FORM_URLENCODED = 'application/x-www-form-urlencoded'


def absolute_url(url):
    return url.startswith(('http://', 'https://'))


def parse_utf8_qsl(s):
    d = dict(parse_qsl(s))

    for k, v in d.items():
        if isinstance(k, unicode) and isinstance(v, unicode):
            # skip this iteration if we have no keys or values to update
            continue
        d.pop(k)
        if not isinstance(k, unicode):
            k = unicode(k, 'utf-8')
        if not isinstance(v, unicode):
            v = unicode(v, 'utf-8')
        d[k] = v
    return d
