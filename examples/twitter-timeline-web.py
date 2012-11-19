"""
Example to demonstrate using twitter oauth as a desktop app or a web app.

Be sure to update with your consumer key/secret and your callback.
from flask import Flask, request, redirect, url_for, session
"""
from flask import Flask, request, redirect, url_for, session
from rauth.service import OAuth1Service

twitter = OAuth1Service(
    name='twitter',
    consumer_key='PUT YOUR KEY',
    consumer_secret='PUT YOUR SECRET',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize')

app = Flask(__name__)
app.debug = True
app.secret_key = 'SSssh its a secret'


@app.route('/get_access_tokens')
def access():
    app.logger.debug('get twitter access tokens\n'
                     '{}\n{}\n'.format(session.get('requst_token', None),
                                       session.get('request_token_secret',
                                                   None)))

    token = request.args.get('oauth_token', None)
    verifier = request.args.get('oauth_verifier', None)

    if session.get('request_token') and (token and verifier):
        print 'TOKEN: ', token
        print 'VERIFIER: ', verifier

        resp = twitter.get_access_token(
            'POST',
            request_token=session.get('request_token'),
            request_token_secret=session.get('request_token_secret'),
            data={'oauth_verifier': verifier}
        )

        assert resp.response.status_code == 200, resp.response.reason
        data = resp.content

        session.pop('request_token_secret', None)
        session.pop('request_token', None)

        session['access_token'] = data['oauth_token']
        session['access_token_secret'] = data['oauth_token_secret']
        print session['access_token'], session['access_token_secret']

        return redirect(url_for('timeline'))
    else:
        app.logger.debug('redirecting to authorize')
        return redirect(url_for('authorize'))


@app.route('/')
def timeline():
    app.logger.debug('display twitter time line:\n'
                     '{}\n{}\n'.format(session.get('access_token', None),
                                       session.get('access_token_secret',
                                                   None)))

    if not session.get('access_token'):
        return redirect(url_for('authorize'))

    include_rts = 1   # Include retweets
    tweet_count = 10  # 10 tweets

    response = twitter.get('https://api.twitter.com/1/statuses/'
                           'home_timeline.json',
                           params=dict(
                               include_rts=include_rts,
                               tweet_count=10,
                               access_token=access_token,
                               access_token_secret=access_token_secret))

    tweets = ''

    for i, tweet in enumerate(response.content, 1):
        handle = tweet['user']['screen_name'].encode('utf-8')
        text = tweet['text'].encode('utf-8')
        tweets += '{0}. @{1} - {2}</br>'.format(i, handle, text)
    return tweets


@app.route('/authorize')
def authorize():
    app.logger.debug('authorize app in twitter')
    """
    Request tokens as a desktop app

    session['request_token'], session['request_token_sercret'] =
        twitter.get_request_token(method='GET')
    """
    session['request_token'], session['request_token_sercret'] = \
        twitter.get_request_token(method='GET',
                                  oauth_callback='YOUR URL or '
                                  'IP/get_access_tokens')

    authorize_url = twitter.get_authorize_url(session['request_token'])

    return redirect(authorize_url)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
