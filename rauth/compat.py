'''
    rauth.compat
    -----------

    Single point of python 2/3 compability tricks
'''

try:  # pragma: no cover
    from urlparse import parse_qsl, urlsplit, urlunsplit
    from urllib import quote, urlencode
    # avoid pyflakes complaint about redefination
    (parse_qsl, urlsplit, urlunsplit, quote, urlencode)
except ImportError:  # pragma: no cover
    from urllib.parse import parse_qsl, urlsplit, urlunsplit, quote, urlencode

try:  # pragma: no cover
    unicode = unicode
    basestring = basestring
    hstr = lambda x: x
except NameError:  # pragma: nocover
    unicode = str
    basestring = str

    def hstr(s):
        '''Converts argument to a type suitable for feeding hash methods.

            :param s: object to be converted
        '''
        return bytes(s, 'ascii')

__all__ = (
    parse_qsl,
    urlsplit,
    urlunsplit,
    quote,
    urlencode,
    unicode,
    basestring,
    hstr
)
