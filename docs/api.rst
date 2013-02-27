.. _api:

API
===

.. module:: rauth

The API is exposed via service wrappers, which provide convenient OAuth 1.0,
2.0, and Ofly flow methods as well as session management.

Each service type has specialized Session objects, which may be used directly.

OAuth 1.0 Services
--------------------

.. autoclass:: rauth.OAuth1Service
    :inherited-members:

OAuth 2.0 Services
------------------

.. autoclass:: rauth.OAuth2Service
    :inherited-members:

Ofly Services
-------------

.. autoclass:: rauth.OflyService
    :inherited-members:

OAuth 1.0 Sessions
------------------

.. autoclass:: rauth.OAuth1Session
    :inherited-members:

OAuth 2.0 Sessions
------------------

.. autoclass:: rauth.OAuth2Session
    :inherited-members:

Ofly Sessions
------------------

.. autoclass:: rauth.OflySession
    :inherited-members:
