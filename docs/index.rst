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

    $ pip install rauth

Or if you must::

    $ easy_install rauth


Usage
-----

The easiest way to get started is by setting up a service wrapper. To do so
simply import the service container object:

.. code-block:: python
    
    from rauth.service import OAuth2Service

    facebook = OAuth2Service(
        client_id='440483442642551',
        client_secret='cd54f1ace848fa2a7ac89a31ed9c1b61'
        name='facebook',
        authorize_url='https://graph.facebook.com/oauth/authorize',
        access_token_url='https://graph.facebook.com/oauth/access_token',
        base_url='https://graph.facebook.com/')

Using the service wrapper API we can obtain an access token after the
authorization URL has been visited by the client. First generate the
authorization URL:

.. code-block:: python

    url = facebook.get_authorize_url()

Once this URL has been visited and (presumably) the client authorizes the
application an access token can be obtained::

    # the code should be returned upon the redirect from the authorize step,
    # be sure to use it here
    token = facebook.get_access_token(code='foobar')

Here is an example using the OAuth 1.0/a service wrapper:

.. code-block:: python

    from rauth.service import OAuth1Service

    twitter = OAuth1Service(
        consumer_key='J8MoJG4bQ9gcmGh8H7XhMg',
        consumer_secret='7WAscbSy65GmiVOvMU5EBYn5z80fhQkcFWSLMJJu4',
        name='twitter',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authorize',
        request_token_url='https://api.twitter.com/oauth/request_token',
        base_url='https://api.twitter.com/1/')

Now it's possible to obtain request tokens via 
`request_token = twitter.get_request_token()`, generate authorization URIs 
`twitter.get_authorize_url(request_token)`, and finally obtain access
tokens `twitter.get_access_token(request_token, request_token_secret)`.


API
---

The API is exposed via service wrappers, which provide convenient OAuth 1.0,
2.0, and Ofly flow methods as well as session management.

Each service type has specialized Session objects, which may be used directly.

OAuth 2.0 Services
------------------

.. autoclass:: rauth.service.OAuth2Service
    :members:

OAuth 1.0/a Services
--------------------

.. autoclass:: rauth.service.OAuth1Service
    :members:

Ofly Services
-------------

.. autoclass:: rauth.service.OflyService
    :members:

OAuth 2.0 Sessions
------------------

.. autoclass:: rauth.session.OAuth2Session
    :members:

OAuth 1.0 Sessions
------------------

.. autoclass:: rauth.session.OAuth1Session
    :members:

Ofly Sessions
------------------

.. autoclass:: rauth.session.OflySession
    :members:
