"""Typed shapes for outbound-SCIM configuration.

Mirror the SCIM connector template
(``content/connectors/templates/scim/metadata.json``) so callers get IDE/mypy
completion when constructing an ``OutboundSCIMConfigurationData`` dict. All
fields are ``NotRequired`` at the ``TypedDict`` level, but ``base_url`` /
``baseUrl`` is required by the backend on Create — enforce that at the call
site, not in the type. Secret-typed fields (``hmacSecret``, ``awsAccessKeyId``,
``awsSecretAccessKey``, ``rfc9421PrivateKey``) are stored encrypted server-side
and returned masked on Load — never plaintext.
"""

from __future__ import annotations

import sys
from typing import List

# TypedDict is available since 3.8 in typing. Literal is available since 3.8 in
# typing. Python 3.9 remains the floor, so both are safe from the stdlib.
from typing import TypedDict

if sys.version_info >= (3, 11):
    from typing import Literal, NotRequired
else:  # pragma: no cover
    from typing import Literal

    from typing_extensions import NotRequired


OutboundSCIMHTTPAuthMethod = Literal[
    "none",
    "bearerToken",
    "apiKey",
    "basicAuth",
    "oauth2ClientCredentials",
]


class OutboundSCIMUserMapping(TypedDict):
    """One entry in the user attribute mapping. ``srcKey`` may be a dot-path
    (e.g. ``"customAttributes.foo"``)."""

    srcKey: str
    namespace: str
    destKey: str


class OutboundSCIMHeader(TypedDict, total=False):
    """One extra HTTP header sent with every SCIM request. ``secret``-flagged
    headers are stored encrypted server-side."""

    key: str
    value: str
    secret: bool


class OutboundSCIMAPIKeyAuth(TypedDict):
    """API key credential. ``key`` is the header name, ``token`` is the value."""

    key: str
    token: str


class OutboundSCIMBasicAuth(TypedDict):
    """HTTP basic-auth credentials."""

    username: str
    password: str


class OutboundSCIMOAuth2RequestHeader(TypedDict):
    """One extra header sent to the OAuth2 token endpoint."""

    name: str
    value: str


class OutboundSCIMOAuth2ClientCredentials(TypedDict, total=False):
    """OAuth2 client-credentials grant configuration. ``scopes`` is
    space-separated. ``authStyle`` is one of ``"header"`` (default) or
    ``"body"``."""

    clientId: str
    clientSecret: str
    authUrl: str
    scopes: str
    authStyle: Literal["header", "body"]
    tokenRequestHeaders: List[OutboundSCIMOAuth2RequestHeader]


class OutboundSCIMHTTPAuth(TypedDict, total=False):
    """Flat HTTP auth config: ``method`` is the discriminator; the sub-field
    matching ``method`` carries the credentials. Only the sub-field named by
    ``method`` is used at request time — others are ignored server-side."""

    method: OutboundSCIMHTTPAuthMethod
    bearerToken: str
    apiKey: OutboundSCIMAPIKeyAuth
    basicAuth: OutboundSCIMBasicAuth
    oauth2ClientCredentials: OutboundSCIMOAuth2ClientCredentials


class OutboundSCIMConfigurationData(TypedDict, total=False):
    """Provider-specific configuration blob for an outbound SCIM connector.

    Field names mirror the SCIM connector template
    (``content/connectors/templates/scim/metadata.json``). ``baseUrl`` is
    required by the backend on Create. Secret-typed fields (``hmacSecret``,
    ``awsAccessKeyId``, ``awsSecretAccessKey``, ``rfc9421PrivateKey``) are
    stored encrypted server-side and returned masked on Load — never plaintext.
    """

    # SCIM SP root URL, e.g. "https://scim.example.com". Required on Create.
    baseUrl: str
    # Drop unverified phone numbers from outgoing SCIM payloads.
    ignoreUnverifiedPhones: bool
    # Drop unverified emails from outgoing SCIM payloads.
    ignoreUnverifiedEmails: bool
    # Maps Descope user attributes to SCIM attributes.
    userMapping: List[OutboundSCIMUserMapping]
    # HTTP auth used for every SCIM request.
    authentication: OutboundSCIMHTTPAuth
    # Extra HTTP headers sent with every SCIM request. Values may be secret-typed.
    headers: List[OutboundSCIMHeader]
    # HMAC secret; signs the base64-encoded payload — the signature is
    # delivered in the "x-descope-webhook-s256" header. Secret-typed.
    hmacSecret: str
    # AWS Signature V4 signing mode. One of "none" (default) or "credentials".
    awsAuthType: Literal["none", "credentials"]
    # Required when awsAuthType == "credentials". Secret-typed.
    awsAccessKeyId: str
    # Required when awsAuthType == "credentials". Secret-typed.
    awsSecretAccessKey: str
    # AWS service to target (e.g. "lambda", "execute-api"). Required when
    # awsAuthType == "credentials".
    awsService: str
    # Turn on RFC 9421 HTTP Message Signatures.
    rfc9421SigningEnabled: bool
    # PEM private key (ECDSA / Ed25519 / RSA) or HMAC secret. Secret-typed.
    rfc9421PrivateKey: str
    # Key id included in the signature metadata.
    rfc9421KeyId: str
    # HTTP message components covered by the signature (comma-separated, e.g.
    # "@method,@target-uri,@authority"). Empty means defaults.
    rfc9421Components: str
    # How long the signature is valid, in seconds. Default 300.
    rfc9421SignatureTTL: int
    # Disable TLS certificate verification. Do not use in production.
    insecure: bool
