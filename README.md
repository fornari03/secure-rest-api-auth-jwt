# Secure REST API - JWT Authentication

This repository contains a secure REST client-server application that implements JWT authentication and digital signatures using HMAC and RSA. It was developed as part of the Advanced Topics in Cybersecurity course.

## Getting Started

Follow the steps below to set up and run the application:

```bash
git clone git@github.com:fornari03/secure-rest-api-auth-jwt.git
cd secure-rest-api-auth-jwt
```

Run the setup script to configure the environment:

```bash
sh setup.sh
```

```bash
python3 src/server.py
```
## EndPoints and APIs

```bash
https://localhost:4443/login    // api/login
https://localhost:4443/register // api/register
https://localhost:4443/secret   // api/protected
```
