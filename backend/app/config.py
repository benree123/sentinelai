"""Validate deployment settings; local defaults cannot leak into production."""
import os
from urllib.parse import urlparse

def production():
    return os.getenv('SENTINEL_ENV', 'development') == 'production'

def secure_cookies():
    return os.getenv('COOKIE_SECURE', 'true' if production() else 'false').lower() == 'true'

def require_verification():
    return os.getenv('REQUIRE_EMAIL_VERIFICATION', 'true' if production() else 'false').lower() == 'true'

def validate_configuration():
    if os.getenv('SENTINEL_ENV', 'development') not in ('development', 'production'):
        raise RuntimeError('SENTINEL_ENV must be development or production')
    for name in ('COOKIE_SECURE', 'REQUIRE_EMAIL_VERIFICATION'):
        if os.getenv(name, '').lower() not in ('', 'true', 'false'):
            raise RuntimeError(name + ' must be true or false')
    if production():
        if not secure_cookies():
            raise RuntimeError('Production requires Secure cookies and HTTPS')
        key = os.getenv('SENTINEL_JWT_KEY', '')
        try:
            valid = len(bytes.fromhex(key)) >= 32
        except ValueError:
            valid = False
        if not valid:
            raise RuntimeError('Production requires SENTINEL_JWT_KEY with at least 32 random bytes')
        if urlparse(os.getenv('SENTINEL_PUBLIC_URL', '')).scheme != 'https':
            raise RuntimeError('Production requires an HTTPS SENTINEL_PUBLIC_URL')
