# -*- coding: utf-8 -*-
'''
    rauth.utils
    -----------

    General utilities.
'''

from rauth.compat import parse_qsl, unicode


def absolute_url(url):
    return url.startswith(('http://', 'https://'))


def parse_utf8_qsl(s):
    if unicode is str and not isinstance(s, unicode):
        s = unicode(s, 'utf-8')
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
