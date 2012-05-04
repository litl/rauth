'''
    rauth.test_hook
    ---------------

    Test suite for rauth.hook.
'''

from base import RauthTestCase
from rauth.hook import OAuth1Hook

from mock import Mock


class OAuthHookTestCase(RauthTestCase):
    def test_intialize_oauthhook(self):
        # without token
        oauth = OAuth1Hook('123', '345')
        self.assertTrue(hasattr(oauth, 'consumer'))

        # with token
        oauth = OAuth1Hook('123', '345', '321', '654')
        self.assertTrue(hasattr(oauth, 'consumer'))
        self.assertTrue(oauth.token is not None)

    def test_oauth_header_auth(self):
        oauth = OAuth1Hook('123', '345', header_auth=True)
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
        oauth = OAuth1Hook('123', '345')

        # call the instance (this would be a POST)
        self.request.method = 'POST'
        oauth(self.request)
        self.assertTrue('oauth_timestamp' in self.request.data)
        self.assertTrue(('oauth_consumer_key', '123') in
                        self.request.data.items())
        self.assertTrue('oauth_nonce' in self.request.data)
        self.assertTrue(('oauth_version', '1.0') in self.request.data.items())
        self.assertTrue(('oauth_signature_method', 'HMAC-SHA1') in
                        self.request.data.items())

    def test_oauth_get(self):
        oauth = OAuth1Hook('123', '345')

        # call the instance (this would be a GET)
        oauth(self.request)
        full_url = self.request.full_url
        self.assertTrue('oauth_timestamp' in full_url)
        self.assertEqual(full_url.count('oauth_timestamp'), 1)
        self.assertTrue('oauth_consumer_key' in full_url)
        self.assertEqual(full_url.count('oauth_consumer_key'), 1)
        self.assertTrue('oauth_nonce' in full_url)
        self.assertEqual(full_url.count('oauth_nonce'), 1)
        self.assertTrue('oauth_version=1.0' in full_url)
        self.assertEqual(full_url.count('oauth_version=1.0'), 1)
        self.assertTrue('oauth_signature_method=HMAC-SHA1' in full_url)
        self.assertEqual(full_url.count('oauth_signature_method=HMAC-SHA1'), 1)

    def test_oauth_get_with_params(self):
        oauth = OAuth1Hook('123', '345')

        self.request.params['foo'] = 'bar'
        self.request.params['a'] = 'b'
        oauth(self.request)
        full_url = self.request.full_url
        self.assertTrue('oauth_timestamp' in full_url)
        self.assertTrue('oauth_consumer_key' in full_url)
        self.assertTrue('oauth_nonce' in full_url)
        self.assertTrue('oauth_version=1.0' in full_url)
        self.assertTrue('oauth_signature_method=HMAC-SHA1' in full_url)
        self.assertTrue('foo=bar' in full_url)
        self.assertTrue('a=b' in full_url)
        self.assertEqual(full_url.count('foo=bar'), 1)
        self.assertEqual(full_url.count('a=b'), 1)

    def test_oauth_callback(self):
        oauth = OAuth1Hook('123', '345')

        self.request.params = {'oauth_callback': 'http://example.com/callback'}
        oauth(self.request)
        oauth_callback = self.request.oauth_params['oauth_callback']
        self.assertEqual('http://example.com/callback', oauth_callback)

        self.request.data = {'oauth_callback': 'http://example.com/callback'}
        oauth(self.request)
        oauth_callback = self.request.oauth_params['oauth_callback']
        self.assertEqual('http://example.com/callback', oauth_callback)

    def test_oauth_with_token(self):
        oauth = OAuth1Hook('123', '345', '321', '654')
        oauth(self.request)
        full_url = self.request.full_url
        self.assertTrue(oauth.token.key is not None)
        self.assertTrue('oauth_token' in full_url)
        self.assertEqual('321', self.request.oauth_params['oauth_token'])
        self.assertTrue('oauth_verifier' in full_url)
        self.assertEqual('', self.request.oauth_params['oauth_verifier'])

        # test with a verifier
        oauth.token.verifier = '4242'
        oauth(self.request)
        self.assertEqual('4242', self.request.oauth_params['oauth_verifier'])

    def test_unique_nonce(self):
        oauth = OAuth1Hook('123', '345')
        oauth(self.request)
        first_nonce = self.request.oauth_params['oauth_nonce']
        oauth(self.request)
        second_nonce = self.request.oauth_params['oauth_nonce']
        self.assertTrue(first_nonce != second_nonce)

    def test_params_or_data_as_lists(self):
        oauth = OAuth1Hook('123', '345')
        self.request.params = [('foo', 'bar')]
        self.request.data = [('foo', 'bar')]
        self.assertTrue(isinstance(self.request.params, list))
        self.assertTrue(isinstance(self.request.data, list))
        oauth(self.request)
        self.assertTrue(isinstance(self.request.params, dict))
        self.assertTrue(isinstance(self.request.data, dict))
        self.assertTrue(('foo', 'bar') in self.request.params.items())

    def test_params_or_data_as_strings(self):
        oauth = OAuth1Hook('123', '345')
        self.request.params = 'foo=bar'
        self.request.data = 'foo=bar'
        self.assertTrue(isinstance(self.request.params, str))
        self.assertTrue(isinstance(self.request.data, str))
        oauth(self.request)
        self.assertTrue(isinstance(self.request.params, dict))
        # unaltered because we don't have a POST
        self.assertTrue(isinstance(self.request.data, str))
        self.assertTrue(('foo', 'bar') in self.request.params.items())

    def test_params_or_data_as_lists_post(self):
        self.request.method = 'POST'
        oauth = OAuth1Hook('123', '345')
        self.request.params = [('foo', 'bar')]
        self.request.data = [('foo', 'bar')]
        self.assertTrue(isinstance(self.request.params, list))
        self.assertTrue(isinstance(self.request.data, list))
        oauth(self.request)
        self.assertTrue(isinstance(self.request.data, dict))
        self.assertTrue(('foo', 'bar') in self.request.data.items())

    def test_params_or_data_as_strings_post(self):
        self.request.method = 'POST'
        oauth = OAuth1Hook('123', '345')
        self.request.params = 'foo=bar'
        self.request.data = 'foo=bar'
        self.assertTrue(isinstance(self.request.params, str))
        self.assertTrue(isinstance(self.request.data, str))
        oauth(self.request)
        self.assertTrue(isinstance(self.request.data, dict))
        self.assertTrue(('foo', 'bar') in self.request.data.items())

    def test_custom_signature_object(self):
        some_signature = Mock()
        oauth = OAuth1Hook('123', '345', signature=some_signature)
        self.assertTrue(oauth.signature is some_signature)

    def test_authorization_realm(self):
        oauth = OAuth1Hook('123', '345', header_auth=True)
        oauth(self.request)
        self.assertTrue('OAuth realm="http://example.com/' in
                        self.request.headers['Authorization'])
