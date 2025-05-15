import sqlite3
import os
import hashlib
from typing import Optional, Dict

DATABASE_NAME = 'users.db'

# Cria o banco de dados e a tabela de usuários se não existir
def init_db():
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        conn.commit()

# Encontra um usuário no banco de dados
def find_user_db(username: str) -> Optional[Dict]:
    with sqlite3.connect(DATABASE_NAME) as conn:
        conn.row_factory = sqlite3.Row  # Para retornar dicionários
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        return dict(user) if user else None

def add_user(username, password):
    salt = os.urandom(16).hex()  # Salt aleatório
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
            (username, password_hash, salt)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:  # Usuário já existe
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT password_hash, salt FROM users WHERE username = ?',
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    stored_hash, salt = result
    # Gera o hash com a senha fornecida + salt armazenado
    test_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    
    return test_hash == stored_hash

# Função para criar um usuário admin padrão
def create_admin_user():
    username = "admin"
    password = "admin@123"  # Senha padrão para o admin

    if not find_user_db(username):
        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256((salt + password).encode()).hexdigest()

        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
            ''', (username, password_hash, salt))
            conn.commit()

init_db()
create_admin_user()