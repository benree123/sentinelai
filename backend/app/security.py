import hashlib, hmac, secrets, base64, json, time

def jwt_encode(session, key):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=').decode()
    header = encode({'alg': 'HS256', 'typ': 'JWT'})
    body = encode({'sid': session, 'exp': int(time.time()) + 900, 'iss': 'sentinelai', 'aud': 'sentinel-web'})
    signed = header + '.' + body
    signature = base64.urlsafe_b64encode(hmac.new(key, signed.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
    return signed + '.' + signature

def jwt_decode(token, key):
    try:
        if not isinstance(token, str) or len(token) > 4096:
            return None
        header, body, signature = token.split('.')
        metadata = json.loads(base64.urlsafe_b64decode(header + '='*(-len(header)%4)))
        if metadata != {'alg':'HS256', 'typ':'JWT'}:
            return None
        expected = base64.urlsafe_b64encode(hmac.new(key, (header+'.'+body).encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(base64.urlsafe_b64decode(body + '='*(-len(body)%4)))
        if claims['exp'] <= time.time() or claims['iss'] != 'sentinelai' or claims['aud'] != 'sentinel-web':
            return None
        return claims['sid']
    except (ValueError, KeyError, TypeError):
        return None

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600_000)
    return f'pbkdf2_sha256$600000${salt}${derived.hex()}'

def verify_password(password: str, encoded: str) -> bool:
    _, iterations, salt, expected = encoded.split('$')
    actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(iterations)).hex()
    return hmac.compare_digest(actual, expected)

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
