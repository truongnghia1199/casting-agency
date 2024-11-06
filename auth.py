import json
from flask import request
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'dev-xpyou6at2p5okktq.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'casting-agency'

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'AUTHORIZATION MALFORMED'
        }, 401)
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'TOKEN EXPIRED'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'INCORRECT CLAIMS. PLEASE, CHECK THE AUDIENCE AND ISSUER'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'UNABLE TO PARSE AUTHENTICATION TOKEN'
            }, 400)
    raise AuthError({
        'code': 'invalid_header',
                'description': 'UNABLE TO FIND THE APPROPRIATE KEY'
    }, 400)

def get_token_auth_header():
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError('MUST HAVE AUTHORIZATION', 401)
    if not auth.startswith('Bearer'):
        raise AuthError('AUTHORIZATION MUST START WITH BEARER', 401)
    if not auth.split(' ')[1]:
        raise AuthError('TOKEN IS REQUIRED', 401)
    return auth.split(' ')[1]


def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError('PERMISSIONS MUST HAVE IN PAYLOAD', 401)
    if permission not in payload['permissions']:
        raise AuthError('PERMISSION NOT FOUND', 401)
    return True


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
