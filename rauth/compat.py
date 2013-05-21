# -*- coding: utf-8 -*-
'''
    rauth.compat
    ------------

    A module providing tools for cross-version compatibility.
'''
import sys

_ver = sys.version_info

#: Python 2.x?
is_py2 = (_ver[0] == 2)

#: Python 3.x?
is_py3 = (_ver[0] == 3)


if is_py2:  # pragma: no cover
    from urllib import quote, urlencode
    from urlparse import parse_qsl, urlsplit, urlunsplit, urljoin

    builtin_str = str
    bytes = str
    str = unicode
    basestring = basestring
    numeric_types = (int, long, float)

    def iteritems(d):
        return d.iteritems()

elif is_py3:  # pragma: no cover
    from urllib.parse import (quote, urlencode, parse_qsl, urlsplit,
                              urlunsplit, urljoin)

    # placate pyflakes
    (quote, urlencode, parse_qsl, urlsplit, urlunsplit, urljoin)

    builtin_str = str
    str = str
    bytes = bytes
    basestring = (str, bytes)
    numeric_types = (int, float)

    def iteritems(d):
        return d.items()
