Upgrading Rauth
===============

Rauth is continually being improved upon. Sometimes these improvements require
breaking changes from release to release. Herein we document these changes and
steps you can take to port your code to newer releases.

In order to upgrade you may use::

    $ pip install -U rauth

or::

    $ easy_install -U rauth


Version 0.5.0
-------------

This release will bring support for Requests v1.x to rauth. The changes in
Requests API are fairly significant and as a direct result the changes to the
rauth API in this release are extensive.

First and foremost Requests v1.x largely does away with hooks (and does away
with the specific hook rauth was previously relying on). As such we have
completely moved away from the hook infrastructure and have replaced it with
custom Session objects. These objects offer some nice benefits such as
keep-alive.

Service wrappers have been restructured to produce instances of their
respective Session objects. This is done via the :meth:`Session.get_session`
method. Much of this happens behind the scenes, in a way that's opaque to the
API consumer. That is, making a call over the request method will automatically
generate or retrieve an appropriately initialized `Session` instance.

OAuth2Service no longer accepts `consumer_id` and `consumer_secret` in place of
`client_id` and `client_secret`. You must update your code if you were using
the old names. This is because the OAuth 2 spec defines these names very
clearly. We had previously used the same names as the OAuth1Service wrapper in
order to remain consistent between wrappers. However this not inline with the
spec and has been deprecated since 0.4.x.

Importantly, service wrappers have done away with almost all *ad hoc* named
arguments. This means that grant types, response codes, and other, often
required, OAuth parameters are **not** provided by default. These were removed
because there were too many special cases and the code became unmanagable.
Specifically there are cases where some parameters are required but others
where these parameters become optional: we can't resonably handle every case in
the library. Instead the consumer should try to manage this themselves by
passing in the required parameters explicitly. This is mostly only applicable
to OAuth2. That said some may be added back in where appropriate. While
porting code, be aware that you must be explicit about these parameters.

Access tokens are always passed in as named arguments now. Whereas previously
this was inconsistent between wrappers and methods. (Note: Ofly does not use
access tokens, but does use an oflyUserid parameter in its place.) If you do
not provide an access token for OAuth1 and OAuth2, the wrapper will attempt to
use the value bound to :attr:`Session.access_token`. Passing in a `None`-type
token is valid, to allow for request and access token calls on OAuth1 and
OAuth2, respectively.

Ofly now requires a `user_id` parameter when invoking the `request` method.
This is because there are no valid calls made over the Ofly protocol that
exclude this parameter. (There is no request token and no access token and the
initial authorize URL is built client-side.)

Additionally there are changes to Requests itself which are mostly beyond the
scope of this document. However it is worth noting you can parse a JSON
response via `r.json()`. The examples have been updated to demonstrate this.
