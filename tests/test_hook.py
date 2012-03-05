'''
    webauth.test_hook
    -----------------

    Test suite for webauth.hook.
'''

from base import WebauthTestCase
from webauth.hook import OAuthHook

from mock import Mock


class OAuthHookTestCase(WebauthTestCase):
    def test_intialize_oauthhook(self):
        # without token
        oauth = OAuthHook('123', '345')
        self.assertTrue(hasattr(oauth, 'consumer'))

        # with token
        oauth = OAuthHook('123', '345', '321', '654')
        self.assertTrue(hasattr(oauth, 'consumer'))
        self.assertTrue(oauth.token is not None)

    def test_oauth_header_auth(self):
        oauth = OAuthHook('123', '345', header_auth=True)
        self.assertTrue(oauth.header_auth)
        oauth(self.request)
        auth_header = self.request.headers['Authorization']
        self.assertTrue(auth_header is not None)
        self.assertTrue('oauth_timestamp' in auth_header)
        self.assertTrue('oauth_consumer_key="123"' in auth_header)
        self.assertTrue('oauth_nonce' in auth_header)
        self.assertTrue('oauth_version="1.0"' in auth_header)
        self.assertTrue('oauth_signature_method="HMAC-SHA1"' in auth_header)

    def test_oauth_post(self):
        oauth = OAuthHook('123', '345')

        # call the instance (this would be a POST)
        self.request.method = 'POST'
        oauth(self.request)
        self.assertTrue('oauth_timestamp' in self.request.data)
        self.assertEqual('123', self.request.data['oauth_consumer_key'])
        self.assertTrue('oauth_nonce' in self.request.data)
        self.assertTrue('oauth_version' in self.request.data)
        self.assertEqual('1.0', self.request.data['oauth_version'])
        self.assertTrue('oauth_signature_method' in self.request.data)
        self.assertEqual('HMAC-SHA1',
                         self.request.data['oauth_signature_method'])

    def test_oauth_get(self):
        oauth = OAuthHook('123', '345')

        # call the instance (this would be a GET)
        oauth(self.request)
        self.assertTrue('oauth_timestamp' in self.request.url)
        self.assertTrue('oauth_consumer_key' in self.request.url)
        self.assertTrue('oauth_nonce' in self.request.url)
        self.assertTrue('oauth_version=1.0' in self.request.url)
        self.assertTrue('oauth_signature_method=HMAC-SHA1' in self.request.url)

    def test_oauth_callback(self):
        oauth = OAuthHook('123', '345')

        self.request.params = {'oauth_callback': 'http://example.com/callback'}
        oauth(self.request)
        oauth_callback = self.request.oauth_params['oauth_callback']
        self.assertEqual('http://example.com/callback', oauth_callback)

        self.request.data = {'oauth_callback': 'http://example.com/callback'}
        oauth(self.request)
        oauth_callback = self.request.oauth_params['oauth_callback']
        self.assertEqual('http://example.com/callback', oauth_callback)

    def test_oauth_with_token(self):
        oauth = OAuthHook('123', '345', '321', '654')
        oauth(self.request)
        self.assertTrue(oauth.token.key is not None)
        self.assertTrue('oauth_token' in self.request.url)
        self.assertEqual('321', self.request.oauth_params['oauth_token'])
        self.assertTrue('oauth_verifier' in self.request.url)
        self.assertEqual('', self.request.oauth_params['oauth_verifier'])

        # test with a verifier
        oauth.token.verifier = '4242'
        oauth(self.request)
        self.assertEqual('4242', self.request.oauth_params['oauth_verifier'])

    def test_unique_nonce(self):
        oauth = OAuthHook('123', '345')
        oauth(self.request)
        first_nonce = self.request.oauth_params['oauth_nonce']
        oauth(self.request)
        second_nonce = self.request.oauth_params['oauth_nonce']
        self.assertTrue(first_nonce != second_nonce)

    def test_params_or_data_as_lists(self):
        oauth = OAuthHook('123', '345')
        self.request.params = [('foo', 'bar')]
        self.request.data = [('foo', 'bar')]
        self.assertTrue(isinstance(self.request.params, list))
        self.assertTrue(isinstance(self.request.params, list))
        oauth(self.request)
        self.assertTrue(isinstance(self.request.params, dict))
        self.assertTrue(isinstance(self.request.data, dict))

    def test_custom_signature_object(self):
        some_signature = Mock()
        oauth = OAuthHook('123', '345', signature=some_signature)
        self.assertTrue(oauth.signature is some_signature)

