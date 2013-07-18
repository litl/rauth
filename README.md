# Rauth

A simple Python OAuth 1.0/a, OAuth 2.0, and Ofly consumer library built on top
of Requests.

[![build status](https://secure.travis-ci.org/litl/rauth.png?branch=master)](https://travis-ci.org/#!/litl/rauth)


## Features

* Supports OAuth 1.0/a, 2.0 and [Ofly](http://www.shutterfly.com/documentation/start.sfly)
* Service wrappers for convenient connection initialization
* Authenticated session objects providing nifty things like keep-alive
* Well tested (100% coverage)
* Built on [Requests](https://github.com/kennethreitz/requests) (v1.x)


## Installation

To install:

    $ pip install rauth

Or if you must:

    $ easy_install rauth


## Example Usage

Let's get a user's Twitter timeline. Start by creating a service container 
object:

```python
from rauth import OAuth1Service

# Get a real consumer key & secret from https://dev.twitter.com/apps/new
twitter = OAuth1Service(
    name='twitter',
    consumer_key='J8MoJG4bQ9gcmGh8H7XhMg',
    consumer_secret='7WAscbSy65GmiVOvMU5EBYn5z80fhQkcFWSLMJJu4',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    base_url='https://api.twitter.com/1.1/')
```

Then get an OAuth 1.0 request token:

```python
request_token, request_token_secret = twitter.get_request_token()
```

Go through the authentication flow.  Since our example is a simple console
application, Twitter will give you a PIN to enter.

```python
authorize_url = twitter.get_authorize_url(request_token)

print 'Visit this URL in your browser: ' + authorize_url
pin = raw_input('Enter PIN from browser: ')  # `input` if using Python 3!
```

Exchange the authorized request token for an authenticated `OAuth1Session`:

```python
session = twitter.get_auth_session(request_token,
                                   request_token_secret,
                                   method='POST',
                                   data={'oauth_verifier': pin})
```

And now we can fetch our Twitter timeline!

```python
params = {'include_rts': 1,  # Include retweets
          'count': 10}       # 10 tweets

r = session.get('statuses/home_timeline.json', params=params)

for i, tweet in enumerate(r.json(), 1):
    handle = tweet['user']['screen_name']
    text = tweet['text']
    print(u'{0}. @{1} - {2}'.format(i, handle, text))
```

Here's the full example: [examples/twitter-timeline-cli.py](https://github.com/litl/rauth/blob/master/examples/twitter-timeline-cli.py).


## Documentation

The Sphinx-compiled documentation is available here: [http://readthedocs.org/docs/rauth/en/latest/](http://readthedocs.org/docs/rauth/en/latest/)


## Contribution

Anyone who would like to contribute to the project is more than welcome.
Basically there's just a few steps to getting started:

1. Fork this repo
2. Make your changes and write a test for them
3. Add yourself to the AUTHORS file and submit a pull request!

Note: Before you make a pull request, please run `make check`. If your code
passes then you should be good to go! Requirements for running tests are in
`requirements-dev@<python-version>.txt`. You may also want to run `tox` to
ensure that nothing broke in other supported environments, e.g. Python 3.

## Copyright and License

Rauth is Copyright (c) 2013 litl, LLC and licensed under the MIT license.
See the LICENSE file for full details.
