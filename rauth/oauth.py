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
from urlparse import parse_qsl, urlsplit, urlunsplit

from rauth.utils import FORM_URLENCODED


class SignatureMethod(object):
    '''A base class for signature methods providing a set of common methods.'''
    def _encode_utf8(self, s):
        if isinstance(s, unicode):
            return s.encode('utf-8')
        return unicode(s, 'utf-8').encode('utf-8')

    def _escape(self, s):
        '''Escapes a string, ensuring it is encoded as a UTF-8 octet.

        :param s: A string to be encoded.
        '''
        return quote(self._encode_utf8(s), safe='~')

    def _remove_qs(self, url):
        '''Removes a query string from a URL before signing.

        :param url: The URL to strip.
        '''
        # split 'em up
        scheme, netloc, path, query, fragment = urlsplit(url)

        # the query string can't be sign as per the spec, kill it
        query = ''

        # and return our query-string-less URL!
        return urlunsplit((scheme, netloc, path, query, fragment))

    def _normalize_request_parameters(self, session, req_kwargs):
        '''
        The OAuth 1.0/a specs indicate that parameter and body data must be
        normalized. The specifics of this operation are detailed in the
        respective specs.

        Here we have to ensure that parameter and body data is properly
        handled. This means that the case of params or data being strings is
        taken care of.

        Essentially this is achieved by checking that `request.data` and
        `request.params` are not strings. This being the case we can then
        construct a unified list of tuples from them.

        Otherwise we build a series intermediary lists of tuples depending on
        the type of `request.params` and `request.data`.

        :param request: The request object that will be normalized.
        '''
        normalized = []

        params = req_kwargs.get('params', {})
        data = req_kwargs.get('data', {})
        headers = req_kwargs.get('headers', {})

        # processing request parameters
        if type(params) == str:
            # parse the string into a list of tuples
            normalized_params = parse_qsl(params)
            for k, v in normalized_params:
                normalized += [(k, v)]
        else:
            # assume params is a list and extract the items
            for k, v in params.items():
                normalized += [(k, v)]

        # processing request data
        if 'Content-Type' in headers and \
                headers['Content-Type'] == FORM_URLENCODED:
            if type(data) == str:
                normalized_data = parse_qsl(data)
                for k, v in normalized_data:
                    normalized += [(k, v)]
            else:
                for k, v in data.items():
                    normalized += [(k, v)]

        # extract values from our list of tuples
        all_normalized = []
        for t in normalized:
            k, v = t
            all_normalized += [(k, v)]

        # add in the params from oauth_params for signing
        for k, v in session.oauth_params.items():
            if (k, v) in all_normalized:
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

    def sign(self, session, method, url, req_kwargs):
        '''Sign request parameters.

        :param session: The session object to sign over.
        :param method: The method of this particular request.
        :param url: The URL of this particular request.
        :param req_kwargs: Keyworded args that will be sent to the request
            method.
        '''

        consumer_secret = session.consumer_secret
        access_token_secret = session.access_token_secret

        # the necessary parameters we'll sign
        url = self._remove_qs(url)
        oauth_params = self._normalize_request_parameters(session, req_kwargs)
        parameters = map(self._escape, [method,
                                        url,
                                        oauth_params])

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
