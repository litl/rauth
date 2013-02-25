# -*- coding: utf-8 -*-
'''
    rauth.oauth
    -----------

    A module providing various OAuth related containers.
'''

import base64
import hmac

from hashlib import sha1
from urllib import quote, urlencode
from urlparse import urlsplit, urlunsplit

from rauth.utils import FORM_URLENCODED


class SignatureMethod(object):
    '''A base class for signature methods providing a set of common methods.'''
    def _encode_utf8(self, s):
        if isinstance(s, unicode):
            return s.encode('utf-8')
        return unicode(s, 'utf-8').encode('utf-8')

    def _escape(self, s):
        '''
        Escapes a string, ensuring it is encoded as a UTF-8 octet.

        :param s: A string to be encoded.
        :type s: str
        '''
        return quote(self._encode_utf8(s), safe='~')

    def _remove_qs(self, url):
        '''
        Removes a query string from a URL before signing.

        :param url: The URL to strip.
        :type url: str
        '''
        scheme, netloc, path, query, fragment = urlsplit(url)

        return urlunsplit((scheme, netloc, path, '', fragment))

    def _normalize_request_parameters(self, session, req_kwargs):
        '''
        This process normalizes the request parameters as detailed in the OAuth
        1.0 spec.

        Essentially we inspect params and data dicts and parse them
        conditionally if they happen to be strings. This is done as Requests
        automatically parses params or data as strings and it is necessary to
        extract all parameters and sort them for signing.

        Additionally we apply a `Content-Type` header to the request of the
        `FORM_URLENCODE` type if the `Content-Type` was previously set, i.e. if
        this is a `POST` or `PUT` request. This ensures the correct header is
        set as per spec.

        Finally we sort the parameters in preparation for signing and return
        a URL encoded string of all normalized parameters.

        :param session: The session object over which to sign the request.
        :type session: :class:`~requests.sessions.Session`
        :param req_kwargs: Request kwargs to normalize.
        :type req_kwargs: dict
        '''
        normalized = []

        params = req_kwargs.get('params', {})
        data = req_kwargs.get('data', {})
        headers = req_kwargs.get('headers', {})

        # process request parameters
        for k, v in params.items():
            normalized += [(k, v)]

        # process request data
        if 'Content-Type' in headers and \
                headers['Content-Type'] == FORM_URLENCODED:
            for k, v in data.items():
                normalized += [(k, v)]

        # extract values from our list of tuples
        all_normalized = []
        for t in normalized:
            k, v = t
            all_normalized += [(k, v)]

        # add in the params from oauth_params for signing
        for k, v in session.oauth_params.items():
            if (k, v) in all_normalized:  # pragma: no cover
                continue
            all_normalized += [(k, v)]

        # sort the params as per the OAuth 1.0/a spec
        all_normalized.sort()

        # finally encode the params as a string
        return urlencode(all_normalized, True).replace('+', '%20')


class HmacSha1Signature(SignatureMethod):
    '''
    HMAC-SHA1 Signature Method.

    This is a signature method, as per the OAuth 1.0/a specs. As the name
    might suggest, this method signs parameters with HMAC using SHA1.
    '''
    NAME = 'HMAC-SHA1'

    def sign(self, session, method, req_kwargs):
        '''Sign request parameters.

        :param session: The session object to sign over.
        :type session: :class:`~requests.sessions.Session`
        :param method: The method of this particular request.
        :type method: str
        :param url: The URL of this particular request.
        :type url: str
        :param req_kwargs: Keyworded args that will be sent to the request
            method.
        :type req_kwargs: dict
        '''
        url = req_kwargs['headers']['x-rauth-root-url']

        p, d = req_kwargs['headers'].get('x-rauth-params-data', ({}, {}))
        if p and 'params' in req_kwargs:
            req_kwargs['params'].update(**p)
        elif p:
            req_kwargs.setdefault('params', {})
            req_kwargs['params'].update(**p)

        if d and 'data' in req_kwargs:
            req_kwargs['data'].update(**d)
        elif d:
            req_kwargs.setdefault('data', {})
            req_kwargs['data'].update(**d)

        consumer_secret = session.consumer_secret
        access_token_secret = session.access_token_secret

        # the necessary parameters we'll sign
        url = self._remove_qs(url)

        oauth_params = self._normalize_request_parameters(session, req_kwargs)
        parameters = map(self._escape, [method, url, oauth_params])

        # set our key
        key = self._escape(consumer_secret) + '&'
        if access_token_secret is not None:
            key += self._escape(access_token_secret)

        # build a Signature Base String
        signature_base_string = '&'.join(parameters)

        # hash the string with HMAC-SHA1
        hashed = hmac.new(key, signature_base_string, sha1)

        # return the signature
        return base64.b64encode(hashed.digest())


class RsaSha1Signature(SignatureMethod):
    '''RSA-SHA1 Signature Method. (Not implemented)'''
    NAME = 'RSA-SHA1'

    def __init__(self):
        raise NotImplementedError


class PlaintextSignature(SignatureMethod):
    '''PLAINTEXT Signature Method. (Not implemented)'''
    NAME = 'PLAINTEXT'

    def __init__(self):
        raise NotImplementedError
