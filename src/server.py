from http.server import HTTPServer
from handler import AuthHandler
import ssl
import os
import subprocess

def run():
    if not os.path.exists('certificates/cert.pem') or not os.path.exists('keys/private.pem'):
        subprocess.run(['./generate.sh'], check=True)

    server_address = ('localhost', 4443) # usa a porta 4443 pra não dar conflito com o https padrão
    server = HTTPServer(server_address, AuthHandler)

    # cria o contexto SSL/TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # adiciona o certificado e a chave privada pro SSL/TLS
    context.load_cert_chain(certfile='certificates/cert.pem', keyfile='keys/private.pem')

    # faz o encapsulamento do socket com SSL/TLS
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print("Server is running on https://localhost:4443")
    server.serve_forever()

run()