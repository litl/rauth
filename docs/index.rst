Rauth
=======

.. module:: rauth

Rauth is a package that delivers client support for OAuth 1.0/a, 2.0, and
Ofly. It is built on top of the superb Python Requests.

.. _rauth: https://github.com/litl/rauth
.. _Requests: https://github.com/kennethreitz/requests


Installation
------------
Install the extension with one of the following commands::

    $ easy_install rauth

or alternatively if you have pip installed::

    $ pip install rauth


Usage
-----

Using the package is quite simple. Ensure that Python Requests is installed.
Import the relavent module and start utilizing OAuth endpoints!

The easiest way to get started is by setting up a service wrapper. To do so
simply import the service container object:

.. code-block:: python
    
    from rauth.service import OAuth2Service

    service = OAuth2Service(
               name='example',
               consumer_key='123',
               consumer_secret='456',
               access_token_url='http://example.com/token',
               authorize_url='http://example.com/authorize')

Using the service wrapper API we can obtain an access token after the
authorization URL has been visited by the client. First generate the
authorization URL:

.. code-block:: python

    url = service.get_authorize_url()

Once this URL has been visited and (presumably) the client authorizes the
application an access token can be obtained::

    # the code should be returned upon the redirect from the authorize step,
    # be sure to use it here
    token = service.get_access_token(code='foobar')

Here is an example using the OAuth 1.0/a service wrapper:

.. code-block:: python

    from rauth.service import OAuth1Service

    service = OAuth1Service(
                    'example',
                    consumer_key='123',
                    consumer_secret='456',
                    request_token_url='http://example.com/request_token',
                    access_token_url='http://example.com/access_token',
                    authorize_url='http://example.com/authorize')

Now it's possible to obtain request tokens via 
`service.get_request_token('GET')`, generate authorization URIs 
`service.get_authorize_url(request_token)`, and finally obtain access
tokens `service.get_access_token(request_token, request_token_secret, 'GET')`.

Additionally, an authenticated session, wrapped with the necessary OAuth data
can be returned via `service.get_authenticated_session(access_token,
access_token_secret)`. Bind this to a variable and then call it to make
authenticated requests to service endpoints.

The OAuth hook object is also available if the service wrapper is not needed or
wanted. It can be used as follows:

.. code-block:: python

    from rauth.service import OAuthHook
    import requests
    
    # setup the OAuth Hook
    oauth = OAuthHook(consumer_key='123', consumer_secret='456')
    # attach it to a pre-request hook
    oauth_requests = requests.session(hooks={'pre_request': oauth})

    # begin by getting a request token
    oauth_requests.get('http://example.com/request_token').content

Once the request token is acquired you'll want to update the OAuth Hook and
request session accordingly, providing the `token` and `token_key` parameters
to `OAuth1Hook`.


API
---

The API is split up into service wrappers which provide convenient methods for
interacting with various service providers.

OAuth 2.0 Services
------------------

.. autoclass:: rauth.service.OAuth2Service
    :members:

OAuth 1.0/1.0a Services
-----------------------

.. autoclass:: rauth.service.OAuth1Service
    :members:

Ofly Services
-------------

.. autoclass:: rauth.service.OflyService
    :members:

OAuth1 Hook
-----------

Additionally, for OAuth 1.0/a services, a Requests hook is available for direct
use.

.. autoclass:: rauth.hook.OAuth1Hook
    :members:
