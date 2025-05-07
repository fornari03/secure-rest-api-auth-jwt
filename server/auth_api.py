from user_data import find_user_db

import hashlib
import os


def auth_user(login_username, login_password):
    # considera que login_username e login_password já estão decriptados

    user = find_user_db(login_username) # considera que user está decriptado
    if not user:
        return False

    user_password = user["password"] # user_password é um hash
    salt = user["salt"]
    
    test_hash = hashlib.sha256((salt + login_password).encode()).hexdigest()

    print(test_hash, user_password, sep="\n")

    return test_hash == user_password




#### funções auxiliares para fazer o hash das infos de um novo usuário
#### não serão usadas no código -> TODO: criar função de registrar usuário

def hash_login_password(salt, login_password):
    return hashlib.sha256((salt + login_password).encode()).hexdigest()

def create_salt():
    return os.urandom(16).hex()