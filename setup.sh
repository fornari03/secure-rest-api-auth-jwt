#!/bin/bash

# 1. Instala dependências do sistema
sudo apt-get update > /dev/null
sudo apt-get install -y openssl python3 python3-cryptography > /dev/null

# 2. Cria estrutura de diretórios
mkdir -p keys certificates

# 3. Gera certificados SSL (se não existirem)
if [ ! -f "keys/private.pem" ] || [ ! -f "certificates/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout keys/private.pem \
        -out certificates/cert.pem \
        -days 15 \
        -nodes \
        -subj "/CN=localhost" 2>/dev/null
    
    # Gera chave pública separadamente
    openssl rsa -in keys/private.pem -pubout -out keys/public.pem 2>/dev/null
    
    # Protege a chave privada
    chmod 600 keys/private.pem
fi