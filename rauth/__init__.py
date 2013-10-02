'''
    rauth
    -----

    OAuth 1.0/a, 2.0, and Ofly wrapped around Python Requests. Basic usage:

        >>> import rauth
        >>> service = rauth.OAuth2Service(client_id='foo', client_secret='bar')
        >>> authorize_url = service.get_authorize_url()

        ...

        >>> session = service.get_auth_session(...)
        >>> r = session.get('resource')
        >>> print r.json

'''

__title__ = 'rauth'
__version_info__ = ('0', '6', '2')
__version__ = '.'.join(__version_info__)
__author__ = 'Max Countryman'
__license__ = 'MIT'
__copyright__ = 'Copyright 2013 litl'
__all__ = ['OAuth1Service', 'OAuth2Service', 'OflyService', 'OAuth1Session',
           'OAuth2Session', 'OflySession']

# HACK: setup workaround for the need to have Requests at runtime
try:
    from .service import OAuth1Service, OAuth2Service, OflyService
    from .session import OAuth1Session, OAuth2Session, OflySession

    # placate pyflakes
    (OAuth1Service, OAuth2Service, OflyService, OAuth1Session, OAuth2Session,
     OflySession)
except ImportError:  # pragma: no cover
    pass
