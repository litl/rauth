# Rauth

A simple Python OAuth 1.0/a, OAuth 2.0, and Ofly consumer library built on top
Requests.

[![build status](https://secure.travis-ci.org/litl/rauth.png?branch=master)](https://travis-ci.org/#!/litl/rauth)


## Installation

Install the module with one of the following commands::

    $ pip install rauth

Or if you must::

    $ easy_install rauth


## Features

* Built on [Requests](https://github.com/kennethreitz/requests)
* Supports OAuth 1.0, 1.0a, 2.0 and [Ofly](http://www.shutterfly.com/documentation/start.sfly)
* Service wrappers for convenient connection initialization
* Well tested (100% coverage)


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
    base_url='https://api.twitter.com/1/')
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
pin = raw_input('Enter PIN from browser: ')
```

Exchange the authorized request token for an access token:

```python
access_token, access_token_secret = \
    twitter.get_access_token(method='POST',
                             request_token=request_token,
                             request_token_secret=request_token_secret,
                             data={'oauth_verifier': pin})
```

And now we can fetch our Twitter timeline!

```python
params = {'include_rts': 1,  # Include retweets
          'count': 10}       # 10 tweets

r = twitter.get('statuses/home_timeline.json',
                params=params,
                access_token=access_token,
                access_token_secret=access_token_secret)

for i, tweet in enumerate(r.json(), 1):
    handle = tweet['user']['screen_name'].encode('utf-8')
    text = tweet['text'].encode('utf-8')
    print '{0}. @{1} - {2}'.format(i, handle, text)
```

The full example is in [examples/twitter-timeline.py](https://github.com/litl/rauth/blob/master/examples/twitter-timeline-cli.py).


## Documentation

The Sphinx-compiled documentation is available here: [http://readthedocs.org/docs/rauth/en/latest/](http://readthedocs.org/docs/rauth/en/latest/)


## Contribution

Anyone who would like to contribute to the project is more than welcome.
Basically there's just a few steps to getting started:

1. Fork this repo
2. Make your changes and write a test for them
3. Add yourself to the AUTHORS file and submit a pull request!

Note: it's important that the code base remain well-tested so to this end it's
generaly advisable to include a unit test. To make sure that we retain 100%
coverage run `python setup.py test` before making a pull request. You'll need
to make sure you have pyflakes, pep8, coverage, mock, and nose installed;
`pip install pyflakes pep8 coverage mock nose`.

## Copyright and License

Rauth is Copyright (c) 2013 litl, LLC and licensed under the MIT license.
See the LICENSE file for full details.
