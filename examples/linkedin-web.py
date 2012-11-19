"""
Example to demonstrate using linkedin oauth as a desktop app or a web app.

Be sure to update with your consumer key/secret and your callback.
from flask import Flask, request, redirect, url_for, session

"""
from flask import Flask, request, redirect, url_for, session
from rauth.service import OAuth1Service

LINKEDIN_API_BASE = 'http://api.linkedin.com/v1/'

linkedin = OAuth1Service(
    name='linkedin',
    consumer_key='tjm826j6uzio',
    consumer_secret='1XbHsC7UxtC6EzqW',
    request_token_url='https://api.linkedin.com/uas/oauth/requestToken',
    access_token_url='https://api.linkedin.com/uas/oauth/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth/authenticate')

app = Flask(__name__)
app.debug = True
app.secret_key = 'SSssh its a secret'


@app.route('/get_access_tokens')
def access():
    request_token = request.args.get('oauth_token', None)
    request_token_secret = session['request_token_secret']
    verifier = request.args.get('oauth_verifier', None)

    print 'debug: ', request_token, request_token_secret, verifier

    if request_token and verifier:
        print 'Request TOKEN: ', request_token
        print 'VERIFIER: ', verifier

        resp = linkedin.get_access_token(
            'POST',
            request_token=request_token,
            request_token_secret=request_token_secret,
            data={'oauth_verifier': verifier})

        assert resp.response.status_code == 200, resp.response.reason
        data = resp.content

        access_token = data['oauth_token']
        access_token_secret = data['oauth_token_secret']
        session['access_token'] = access_token
        session['access_token_secret'] = access_token_secret

        print access_token, access_token_secret

        return redirect(url_for('connections'))
    else:
        app.logger.debug('redirecting to authorize')
        return redirect(url_for('authorize'))


@app.route('/')
def connections():

    if not 'access_token' in session:
        return redirect(url_for('authorize'))

    response = linkedin.get(
        LINKEDIN_API_BASE + 'people/~/connections',
        params=dict(format='json',
                    access_token=session.get('access_token'),
                    access_token_secret=session.get('access_token_secret')))

    resp = response.content

    print resp['_total']

    return 'You have: ' + str(resp['_total']) + ' connections.'


@app.route('/authorize')
def authorize():
    app.logger.debug('authorize app in linkedin')
    """
    Request tokens as a desktop app

    """
    request_token, request_token_secret = \
        linkedin.get_request_token(
            method='GET',
            oauth_callback='http://localhost:5000/get_access_tokens',
            data='scope=r_basicprofile+r_emailaddress+r_fullprofile+r_network')

    session['request_token'] = request_token
    session['request_token_secret'] = request_token_secret

    authorize_url = linkedin.get_authorize_url(request_token)

    return redirect(authorize_url)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
