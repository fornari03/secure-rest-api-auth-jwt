from http.server import BaseHTTPRequestHandler
import json
from auth_api import auth_user, register_user, generate_jwt

class AuthHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path == "/api/login":
            self.handle_login()

        elif self.path == "/api/register":
            self.handle_register()
            
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
        body = self.rfile.read(content_length).decode()
        login_body = json.loads(body)

        username = login_body.get("username")  
        password = login_body.get("password")

        if auth_user(username, password):
            token = generate_jwt(username, algorithm="HMAC")
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

    def handle_register(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        register_body = json.loads(body)
        username = register_body.get("username")
        password = register_body.get("password")

        if not username or not password:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Bad Request",
                "message": "Username and password are required.",
            }
            self.wfile.write(json.dumps(res).encode())
            return

        if register_user(username, password):
            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            res = {
                "message": "User registered successfully."
            }
            self.wfile.write(json.dumps(res).encode())
        else:
            self.send_response(409)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Conflit",
                "message": "User already exists.",
            }
            self.wfile.write(json.dumps(res).encode())