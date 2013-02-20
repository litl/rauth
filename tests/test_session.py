# -*- coding: utf-8 -*-
'''
    rauth.test_session
    ------------------

    Test suite for rauth.session.
'''

from base import RauthTestCase
from rauth.session import OAuth1Session, OAuth2Session, OflySession


class OAuth1SessionTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp()

        self.session = OAuth1Session('123', '345')


class OAuth2SessionTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp()

        self.session = OAuth2Session('123', '345')


class OflySessionTestCase(RauthTestCase):
    def setUp(self):
        RauthTestCase.setUp()

        self.session = OflySession('123', '345')
