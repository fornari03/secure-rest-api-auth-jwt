from http.server import BaseHTTPRequestHandler
from datetime import datetime
from auth_api import auth_user, register_user, generate_jwt, verify_jwt, get_jti, add_to_blacklist
from database import is_blacklisted, find_user_db
import json, jwt

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

        elif self.path == "/api/logout":
            self.handle_logout()
            
        else:
            # tentou fazer POST em outro endpoint: Not Found
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Not Found",
                "message": "Endpoint not found.",
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
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Unauthorized",
                "message": "Token is missing or invalid.",
            }
            self.wfile.write(json.dumps(res).encode())
            return
        
        token = auth_header.split(' ')[1]
        algorithm = jwt.get_unverified_header(token).get("alg")
        jti = get_jti(token, algorithm)

        if is_blacklisted(jti):
            self.send_error(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Unauthorized",
                "message": "Token is blacklisted. Please log in again.",
            }
            self.wfile.write(json.dumps(res).encode())
            return

        payload = verify_jwt(token, algorithm)
        if payload is None:
            self.send_error(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Unauthorized",
                "message": "Token is invalid or expired.",
            }
            self.wfile.write(json.dumps(res).encode())
            return
        
        user = find_user_db(payload.get("sub"))
        if user is None:
            self.send_error(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Unauthorized",
                "message": "User not found.",
            }
            self.wfile.write(json.dumps(res).encode())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "user": user["username"],
            "created_at": datetime.strptime(user["created_at"], "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y às %H:%M:%S"),
            "secret_info": "DADOS ULTRA SECRETOS!!!",
        }).encode())
        del payload # remove o payload para não vazar informações
        del user # remove o usuário para não vazar informações
        # redundante, mas é uma boa prática

    def handle_login(self):
        content_length = int(self.headers.get('Content-Length', 0)) # se não tiver, length = 0
        body = self.rfile.read(content_length).decode()
        login_body = json.loads(body)

        username = login_body.get("username")  
        password = login_body.get("password")
        algorithm = login_body.get("algorithm")

        if auth_user(username, password):
            token = generate_jwt(username, algorithm)
            response = {
                "token": token,
                "algorithm": algorithm
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Unauthorized",
                "message": "Failed to authenticate user or algorithm not defined.",
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

    def handle_logout(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            self.send_error(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {
                "error": "Unauthorized",
                "message": "Token is missing or invalid.",
            }
            self.wfile.write(json.dumps(res).encode())
            return
        
        token = auth_header.split(' ')[1]
        algorithm = jwt.get_unverified_header(token).get("alg")
        jti = get_jti(token, algorithm)

        add_to_blacklist(jti)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        res = {
            "message": "Logout successful.",
        }
        self.wfile.write(json.dumps(res).encode())