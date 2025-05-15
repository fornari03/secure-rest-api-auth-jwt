from typing import Optional, Dict
import sqlite3, os, bcrypt

USERS_DATABASE = 'users.db'
BLACKLIST_DATABASE = 'blacklist.db'

# Cria o banco de dados e a tabela de usuários se não existir
def init_db():
    with sqlite3.connect(USERS_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        conn.commit()
    
    with sqlite3.connect(BLACKLIST_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            jti TEXT PRIMARY KEY
        )
        ''')
        conn.commit()

# Adiciona um JTI à blacklist
def add_to_blacklist(jti: str) -> bool:
    try:
        with sqlite3.connect(BLACKLIST_DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO blacklist (jti) VALUES (?)', (jti,))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        # JTI já existe na blacklist
        return False

# Verfifica se o JTI está na blacklist
def is_blacklisted(jti: str) -> bool:
    with sqlite3.connect(BLACKLIST_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM blacklist WHERE jti = ? LIMIT 1', (jti,))
        return cursor.fetchone() is not None

# Encontra um usuário no banco de dados
def find_user_db(username: str) -> Optional[Dict]:
    with sqlite3.connect(USERS_DATABASE) as conn:
        conn.row_factory = sqlite3.Row  # Para retornar dicionários
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        return dict(user) if user else None

def add_user(username, password):
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    conn = sqlite3.connect(USERS_DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:  # Usuário já existe
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = sqlite3.connect(USERS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT password_hash FROM users WHERE username = ?',
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    stored_hash = result[0]
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

# Função para criar um usuário admin padrão
def create_admin_user():
    username = "admin"
    password = "admin@123"  # Senha padrão para o admin
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    with sqlite3.connect(USERS_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)
        ''', (username, password_hash))
        conn.commit()

init_db()
create_admin_user()