"""Utility functions for encoding/decoding JWT tokens.

This module implements the basic JWT token encoding and
decoding functionality. Most function implementations
were inspired by the oauth2client library. It also uses the
crypto capabilities of the oauth2client library for
signing and verifying JWTs. However, unlike oauth2client
this implementation provides more control over JWT headers.
"""
import base64
import json

import httplib2
import six

from oauth2client import client
from oauth2client import crypt
from oauth2client import transport


_cached_http = httplib2.Http(transport.MemoryCache())


def _to_bytes(value, encoding='ascii'):
    result = (value.encode(encoding)
              if isinstance(value, six.text_type) else value)
    if isinstance(result, six.binary_type):
        return result
    else:
        raise ValueError('{0!r} could not be converted to bytes'.format(value))


def _urlsafe_b64encode(raw_bytes):
    raw_bytes = _to_bytes(raw_bytes, encoding='utf-8')
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b'=')


def _urlsafe_b64decode(b64string):
    b64string = _to_bytes(b64string)
    padded = b64string + b'=' * (4 - len(b64string) % 4)
    return base64.urlsafe_b64decode(padded)


def encode(payload, signer, headers=None):
    """Encodes the provided payload into a signed JWT.

    Creates a signed JWT from the given dictionary payload of claims.
    By default this function only adds the 'typ' and 'alg' headers to
    the encoded JWT. The 'headers' argument can be used to set additional
    JWT headers, and override the defaults. This function provides the
    bare minimal token encoding and signing functionality. Any validations
    on individual claims should be performed by the caller.

    Args:
      payload: A dictionary of claims.
      signer: An oauth2client.crypt.Signer instance for signing tokens.
      headers: An dictionary of headers (optional).

    Returns:
      string: A signed JWT token.
    """
    header = {'typ': 'JWT', 'alg': 'RS256'}
    if headers:
        header.update(headers)
    segments = [
        _urlsafe_b64encode(json.dumps(header, separators=(',', ':'))),
        _urlsafe_b64encode(json.dumps(payload, separators=(',', ':'))),
    ]
    signing_input = b'.'.join(segments)
    signature = signer.sign(signing_input)
    segments.append(_urlsafe_b64encode(signature))
    return b'.'.join(segments)


def decode(token):
    """Decodes the provided JWT into dictionaries.

    Parses the provided token and extracts its header values and claims.
    Note that this function does not perform any verification on the
    token content. Nor does it attempt to verify the token signature.
    Th only validation it performs is for the proper formatting/encoding
    of the JWT token, which is necessary to parse it. Simply use this
    function to unpack, and inspect the contents of a JWT.

    Args:
      token: A signed JWT token as a string.

    Returns:
      tuple: A 2-tuple where the first element is a dictionary of JWT headers,
          and the second element is a dictionary of payload claims.

    Raises:
      AppIdentityError: If the token is malformed or badly formatted
    """
    if token.count(b'.') != 2:
        raise crypt.AppIdentityError(('Wrong number of segments'
                                      ' in token: {0}').format(token))
    header, payload, _ = token.split(b'.')
    header_dict = json.loads(_urlsafe_b64decode(header).decode('utf-8'))
    payload_dict = json.loads(_urlsafe_b64decode(payload).decode('utf-8'))
    return (header_dict, payload_dict)


def verify_id_token(id_token, cert_uri, audience=None, kid=None, http=None):
    """Verifies the provided ID token.

    Checks for token integrity by verifying its signature against
    a set of public key certificates. Certificates are downloaded
    from cert_uri, and cached according to the HTTP cache control
    requirements. If provided, the audience and kid fields of the
    ID token are also validated.

    Args:
      id_token: JWT ID token to be validated.
      cert_uri: A URI string pointing to public key certificates.
      audience: Audience string that should be present in the token.
      kid: JWT key ID header to locate the public key certificate.
      http: An httplib2 HTTP client instance.

    Returns:
      dict: A dictionary of claims extracted from the ID token.

    Raises:
      ValueError: Certificate URI is None or empty.
      AppIdentityError: Token integrity check failed.
      VerifyJwtTokenError: Failed to load public keys or invalid kid header.
    """
    if not cert_uri:
        raise ValueError('Certificate URI is required')
    if not http:
        http = _cached_http
    resp, content = http.request(cert_uri)
    if resp.status != 200:
        raise client.VerifyJwtTokenError(
            ('Failed to load public key certificates from URL "{0}". Received '
             'HTTP status code {1}.').format(cert_uri, resp.status))
    str_content = content.decode('utf-8') if isinstance(content, six.binary_type) else content
    certs = json.loads(str_content)
    if kid and kid not in certs:
        raise client.VerifyJwtTokenError(
            'Firebase ID token has "kid" claim which does'
            ' not correspond to a known public key. Most'
            ' likely the ID token is expired, so get a'
            ' fresh token from your client app and try again.')
    return crypt.verify_signed_jwt_with_certs(id_token, certs, audience)
