#!/bin/bash

# 1. Instala dependências do sistema
sudo apt-get update > /dev/null
sudo apt-get install -y openssl python3 python3-cryptography > /dev/null

# 2. Cria estrutura de diretórios
mkdir -p keys certificates

# 3. Gera certificados SSL e RSA (se não existirem)
if [ ! -f "keys/rsa_private.pem" ] || [ ! -f "certificates/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout keys/rsa_private.pem \
        -out certificates/cert.pem \
        -days 15 \
        -nodes \
        -subj "/CN=localhost" 2>/dev/null
    
    # Gera chave pública separadamente
    openssl rsa -in keys/rsa_private.pem -pubout -out keys/rsa_public.pem 2>/dev/null
    
    # Protege a chave privada
    chmod 600 keys/rsa_private.pem
    chmod 644 keys/rsa_public.pem
fi

# 4. Gera chave HMAC (se não existir)
if [ ! -f "keys/hmac_key.pem" ]; then
    # Gera chave HMAC
    openssl rand -out keys/hmac_key.pem 32 2>/dev/null

    # Protege a chave HMAC
    chmod 600 keys/hmac_key.pem
fi