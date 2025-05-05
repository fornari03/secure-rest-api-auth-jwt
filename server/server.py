from http.server import HTTPServer
from handler import AuthHandler

def run():
    server_address = ('localhost', 4443) # usa a porta 4443 pra não dar conflito com o https padrão
    server = HTTPServer(server_address, AuthHandler)

    # TODO: encapsular o socket com TLS para virar https

    print("Server is running on https://localhost:4443")
    server.serve_forever()

run()