'''
    rauth
    -----

    OAuth 1.0/a and 2.0 wrapped around Python Requests.
'''

__title__ = 'rauth'
__version__ = '0.4.13'
__license__ = 'MIT'

from .service import OAuth1Service, OAuth2Service, OflyService

services = (OAuth1Service, OAuth2Service, OflyService)
