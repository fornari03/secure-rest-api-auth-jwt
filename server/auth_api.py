from user_data import find_user_db, add_user_db

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