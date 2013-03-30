# -*- coding: utf-8 -*-
'''
    rauth.compat
    ------------

    A module providing tools for cross-version compatibility.
'''
import sys


if sys.version_info < (3, 0):
    from urllib import quote, urlencode
    from urlparse import parse_qsl, urlsplit, urlunsplit, urljoin

    def is_basestring(astring):
        return isinstance(astring, basestring)

    def iteritems(adict):
        return adict.iteritems()

else:
    from urllib.parse import (
        quote, urlencode, parse_qsl, urlsplit, urlunsplit, urljoin
    )

    def is_basestring(astring):
        return isinstance(astring, (str, bytes))

    def iteritems(adict):
        return adict.items()
