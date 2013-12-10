:orphan:

Rauth
=====

A simple Python OAuth 1.0/a, OAuth 2.0, and Ofly consumer library built on top
of `Requests`_.

.. _rauth: https://github.com/litl/rauth
.. _Requests: https://github.com/kennethreitz/requests

Installation
------------
Install the module with one of the following commands::

    $ pip install rauth

Or if you must::

    $ easy_install rauth


Usage
-----

If you want to check out the complete :ref:`api` documentation, go ahead.

The easiest way to get started is by setting up a service wrapper. To do so
simply import the service container object:

.. code-block:: python
    
    from rauth import OAuth2Service

    facebook = OAuth2Service(
        client_id='440483442642551',
        client_secret='cd54f1ace848fa2a7ac89a31ed9c1b61',
        name='facebook',
        authorize_url='https://graph.facebook.com/oauth/authorize',
        access_token_url='https://graph.facebook.com/oauth/access_token',
        base_url='https://graph.facebook.com/')

Using the service wrapper API we can obtain an access token after the
authorization URL has been visited by the client. First generate the
authorization URL:

.. code-block:: python

    redirect_uri = 'https://www.facebook.com/connect/login_success.html'
    params = {'scope': 'read_stream',
              'response_type': 'code',
              'redirect_uri': redirect_uri}

    url = facebook.get_authorize_url(**params)

Once this URL has been visited and (presumably) the client authorizes the
application an access token can be obtained:

.. code-block:: python

    # the code should be returned upon the redirect from the authorize step,
    # be sure to use it here (hint: it's in the URL!)
    session = facebook.get_auth_session(data={'code': 'foo',
                                               'redirect_uri': redirect_uri})

    print session.get('me').json()['username']

Here is an example using the OAuth 1.0/a service wrapper:

.. code-block:: python

    from rauth import OAuth1Service

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
`twitter.get_authorize_url(request_token)`, and finally obtain an authenticated
session `twitter.get_auth_session(request_token, request_token_secret)`.

.. include:: contents.rst.inc
