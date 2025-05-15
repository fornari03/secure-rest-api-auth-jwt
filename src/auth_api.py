from database import verify_user, add_user, add_to_blacklist
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os, time, jwt

def load_rsa_keys():
    key_dir = "keys"
    private_key_path = os.path.join(key_dir, "rsa_private.pem")
    public_key_path = os.path.join(key_dir, "rsa_public.pem")

    # Carrega a chave privada
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Carrega a chave pública
    with open(public_key_path, "rb") as cert_file:
        public_key = serialization.load_pem_public_key(
            cert_file.read(),
            backend=default_backend()
        )

    return private_key, public_key

RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = load_rsa_keys()
HMAC_SECRET = open("keys/hmac_key.pem", "rb").read()
JWT_EXPIRATION = 3600

def generate_jwt(username, algorithm):
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRATION,
        "jti": str(os.urandom(16).hex()),
    }

    if algorithm == "HS256":
        token = jwt.encode(payload, HMAC_SECRET, algorithm="HS256")
    elif algorithm == "RS256":
        token = jwt.encode(payload, RSA_PRIVATE_KEY, algorithm="RS256")
    else:
        raise ValueError("Apenas HMAC e RSA são suportados.")
        
    return token

def auth_user(login_username, login_password):
    return verify_user(login_username, login_password)

def register_user(login_username, login_password):
    return add_user(login_username, login_password)

def verify_jwt(token, algorithm):
    try:

        if algorithm == "HS256":
            payload = jwt.decode(token, HMAC_SECRET, algorithms=["HS256"])
        elif algorithm == "RS256":
            payload = jwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256"])
        else:
            raise ValueError("Apenas HMAC e RSA são suportados.")
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    
def get_jti(token, algorithm):
    try:
        if algorithm == "HS256":
            payload = jwt.decode(token, HMAC_SECRET, algorithms=["HS256"])
        elif algorithm == "RS256":
            payload = jwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256"])
        else:
            raise ValueError("Apenas HMAC e RSA são suportados.")
        
        return payload.get("jti")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None