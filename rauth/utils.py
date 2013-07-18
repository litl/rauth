# -*- coding: utf-8 -*-
'''
    rauth.utils
    -----------

    General utilities.
'''

from rauth.compat import parse_qsl, is_basestring

from requests.structures import CaseInsensitiveDict as cidict

FORM_URLENCODED = 'application/x-www-form-urlencoded'
ENTITY_METHODS = ('POST', 'PUT', 'PATCH')
OPTIONAL_OAUTH_PARAMS = ('oauth_callback', 'oauth_verifier', 'oauth_version')


def absolute_url(url):
    return url.startswith(('http://', 'https://'))


def parse_utf8_qsl(s):
    d = dict(parse_qsl(s))

    for k, v in d.items():  # pragma: no cover
        if not isinstance(k, bytes) and not isinstance(v, bytes):
            # skip this iteration if we have no keys or values to update
            continue
        d.pop(k)
        if isinstance(k, bytes):
            k = k.decode('utf-8')
        if isinstance(v, bytes):
            v = v.decode('utf-8')
        d[k] = v
    return d


def get_sorted_params(params):
    def sorting_gen():
        for k in sorted(params.keys()):
            yield '='.join((k, params[k]))
    return '&'.join(sorting_gen())


class CaseInsensitiveDict(cidict):
    def __init__(self, d=None):
        lowered_d = {}

        if d is not None:
            if isinstance(d, dict):
                lowered_d = self._get_lowered_d(d)
            elif isinstance(d, list):
                return self.__init__(dict(d))

        return super(CaseInsensitiveDict, self).__init__(lowered_d)

    def _get_lowered_d(self, d):
        lowered_d = {}
        for key in d:
            if is_basestring(key):
                lowered_d[key.lower()] = d[key]
            else:  # pragma: no cover
                lowered_d[key] = d[key]
        return lowered_d

    def setdefault(self, key, default):
        if is_basestring(key):
            key = key.lower()

        super(CaseInsensitiveDict, self).setdefault(key, default)

    def update(self, d):
        super(CaseInsensitiveDict, self).update(self._get_lowered_d(d))
