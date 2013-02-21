'''
    rauth
    -----

    OAuth 1.0/a, 2.0, and Ofly wrapped around Python Requests.
'''

__title__ = 'rauth'
__version__ = '0.5.0'
__license__ = 'MIT'

from rauth.service import OAuth1Service, OAuth2Service, OflyService
from rauth.session import OAuth1Session, OAuth2Session, OflySession

# placate pyflakes
assert OAuth1Service
assert OAuth2Service
assert OflyService

assert OAuth1Session
assert OAuth2Session
assert OflySession
