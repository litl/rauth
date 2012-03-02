# Webauth: OAuth 1.0/a for Python

Webauth is a package providing OAuth 1.0/a consumer support. The package is
written as a hook over the superb Python Requests package.


## Installation

Install the package with one of the following commands:

    $ python setup.py install

or

    $ pip install webauth (not yet!)


## Usage

Using the package is quite simple. Ensure that Python Requests is installed.
Import the relavent module and start utilizing OAuth endpoints!

    from webauth import OAuthHook
    import requests
    
    # setup the OAuth Hook
    oauth = OAuthHook(consumer_key='123', consumer_secret='456')
    # attach it to a pre-request hook
    oauth_requests = requests.session(hooks={'prehook': oauth})

    # begin by getting a request token
    oauth_requests.get('http://example.com/request_token').content

Once the request token is acquired you'll want to update the OAuth Hook and
request session accordingly, providing the `token` and `token_key` parameters
to `OAuthHook`.


## Documentation

The Sphinx-compiled documentation is available here: (not yet!)
