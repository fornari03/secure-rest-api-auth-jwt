USERS_DATA = [
        {
        "username": "username1",
        "password": "93f8fc519df4054d92d3093ad8cd192b298102e7056264a4883d8ed4fa5c4f0f", # hash de password1 com o salt
        "salt": "7dc4cf75de960c26cca2d0330d5da92a"
        },
    ]

# TODO: transformar em um banco de dados real

def find_user_db(username):
    for user in USERS_DATA:
        if user.get("username") == username:
            return user
    return None