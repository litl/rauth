# Webauth: OAuth 1.0/a, 2.0, and Ofly for Python

Webauth is a package providing OAuth 1.0/a, 2.0, and Ofly consumer support. The
package is wrapped around the superb Python Requests.


## Installation

Install the package with one of the following commands:

    $ python setup.py install

or

    $ pip install webauth (not yet!)


## Usage

Using the package is quite simple. Ensure that Python Requests is installed.
Import the relavent module and start utilizing OAuth endpoints!

The easiest way to get started is by setting up a service wrapper. To do so
simply import the service container object:

    from webauth import OAuth2Service

    service = OAuth2Service(
               name='example',
               consumer_key='123',
               consumer_secret='456',
               access_token_url='http://example.com/token',
               authorize_url='http://example.com/authorize')

Using the service wrapper API we can obtain an access token after the
authorization URL has been visited by the client. First generate the
authorization URL:

    url = service.get_authorize_url()

Once this URL has been visited and (presumably) the client authorizes the
application an access token can be obtained:

    # the code should be returned upon the redirect from the authorize step,
    # be sure to use it here
    token = service.get_access_token(code='foobar')

Here is an example using the OAuth 1.0/a service wrapper:

    from webauth import OAuth1Service

    service = OAuth1Service(
                    'example',
                    consumer_key='123',
                    consumer_secret='456',
                    request_token_url='http://example.com/request_token',
                    access_token_url='http://example.com/access_token',
                    authorize_url='http://example.com/authorize')

Now it's possible to obtain request tokens via 
`service.get_request_token('GET')`, generate authorization URIs 
`service.get_authorization_url(request_token)`, and finally obtain access
tokens `service.get_access_token(request_token, request_token_secret, 'GET')`.

## Documentation

The Sphinx-compiled documentation is available here: (not yet!)


## Copyright and License

Webauth is Copyright (c) 2012 litl, LLC and licensed under the MIT license.
See the LICENSE file for full details.
