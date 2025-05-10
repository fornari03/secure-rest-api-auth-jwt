from user_data import find_user_db, add_user_db

import hashlib
import os
import jwt
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

JWT_SECRET_HMAC = os.urandom(32)
JWT_EXPIRATION = 3600

def load_rsa_keys():
    key_dir = "keys"
    private_key_path = os.path.join(key_dir, "private.pem")
    public_key_path = os.path.join(key_dir, "public.pem")

    # Cria o diretório se não existir
    os.makedirs(key_dir, exist_ok=True)

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Salva a chave privada
        with open(private_key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Salva a chave pública
        with open(public_key_path, "wb") as cert_file:
            cert_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    else:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        with open(public_key_path, "rb") as cert_file:
            public_key = serialization.load_pem_public_key(
                cert_file.read(),
                backend=default_backend()
            )

    return private_key, public_key

RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = load_rsa_keys()

def generate_jwt(username, algorithm="HMAC"):
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRATION
    }

    if algorithm == "HMAC":
        token = jwt.encode(payload, JWT_SECRET_HMAC, algorithm="HS256")
    elif algorithm == "RSA":
        token = jwt.encode(payload, RSA_PRIVATE_KEY, algorithm="RS256")
    else:
        raise ValueError("Apenas HMAC e RSA são suportados.")
    
    return token

def auth_user(login_username, login_password):
    # considera que login_username e login_password já estão decriptados

    user = find_user_db(login_username) # considera que user está decriptado
    if not user:
        return False

    user_password = user["password"] # user_password é um hash
    salt = user["salt"]
    
    test_hash = hashlib.sha256((salt + login_password).encode()).hexdigest()

    return test_hash == user_password


def register_user(login_username, login_password):
    # considera que login_username e login_password já estão decriptados

    if find_user_db(login_username):
        return False # usuário já existe
    
    salt = os.urandom(16).hex()
    user_password = hashlib.sha256((salt + login_password).encode()).hexdigest()
    
    add_user_db({
        "username": login_username,
        "password": user_password,
        "salt": salt
    })

    return True # criou o usuário