USERS_DATA = [
        {
        "username": "username1",
        "password": "password1"
        },

        {
        "username": "username2",
        "password": "password2"
        },
    ]

# TODO: transformar em um banco de dados real

def find_user_db(username):
    for user in USERS_DATA:
        if user.get("username") == username:
            return user
    return None