import os
import json

from http.server import BaseHTTPRequestHandler
from auth_api import auth_user, register_user, generate_jwt, verify_jwt

class AuthHandler(BaseHTTPRequestHandler):
    def _set_headers(self, content_type='application/json'):
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', 'https://localhost:4443')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def do_POST(self):
        # Verifica se o endpoint é /api/login ou /api/register
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

    def serve_html_file(self, filename):
        try:
            with open(f"static/{filename}", 'rb') as file:
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(file.read())
        except FileNotFoundError:
            self.send_error(404, "Página não encontrada")

    def do_GET(self):
        if self.path == "/api/protected":
            self.handle_protected()
        elif self.path in ["/", "/login"]:
            self.serve_html_file("login.html")
        elif self.path == "/register":
            self.serve_html_file("register.html")
        elif self.path == "/secret":
            self.serve_html_file("secret.html")
        else:
            self.send_error(404)

    def handle_protected(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            self.send_error(401)
            return
        
        token = auth_header.split(' ')[1]
        if not verify_jwt(token):  # Implemente esta função no auth_api.py
            self.send_error(401)
            return
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "user": "admin",
            "password": "admin@123",
            "secret_info": "DADOS ULTRA SECRETOS!!!",
        }).encode())

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