from http.server import HTTPServer
from handler import AuthHandler
import ssl

def run():

    server_address = ('0.0.0.0', 4443)
    server = HTTPServer(server_address, AuthHandler)

    # cria o contexto SSL/TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # adiciona o certificado e a chave privada pro SSL/TLS
    context.load_cert_chain(certfile='certificates/cert.pem', keyfile='keys/rsa_private.pem')

    # faz o encapsulamento do socket com SSL/TLS
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print("Server is running on https://localhost:4443")
    server.serve_forever()

run()