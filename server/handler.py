from http.server import BaseHTTPRequestHandler
import json
from urllib.parse import urlparse
from auth_api import auth_user
from user_data import USERS_DATA

class AuthHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path == "/api/login":
            self.handle_login()
        else:
            # tentou fazer POST em outro endpoint: Forbidden
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Forbidden",
                "message": "Endpoint not allowed for POST."
            }
            self.wfile.write(json.dumps(res).encode())


    def handle_login(self):
        content_length = int(self.headers.get('Content-Length', 0)) # se não tiver, length = 0
        body = self.rfile.read(content_length)
        login_body = json.loads(body)

        username = login_body.get("username")  
        password = login_body.get("password")

        if auth_user(username, password):
            token = {"username": username, "password": password} # TODO: fazer o token JWT
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode())
        else:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Unauthorized",
                "message": "Failed to authenticate user.",
            }
            self.wfile.write(json.dumps(res).encode())
