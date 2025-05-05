from user_data import find_user_db

def auth_user(username, password):

    user = find_user_db(username)
    if not user:
        return False

    # TODO: fazer a verificação hash da senha
    return True
