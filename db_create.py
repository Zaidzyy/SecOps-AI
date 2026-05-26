import sqlite3
import os

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'system_metrics.db')

def create_database():
    # SQLite-
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Tablr metrics 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            timestamp TEXT,
            cpu REAL,
            memory REAL,
            disk REAL,
            network REAL
        )
    ''')

    # Table logs 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            timestamp TEXT,
            log TEXT
        )
    ''')

    # Table users 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )
    ''')

    
    conn.commit()
    conn.close()
    print(f"✅ SecOps-AI: Storage ecosystem initialized successfully. Tables built at: '{DATABASE_PATH}' erstellt.")

if __name__ == '__main__':
    
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    create_database()
