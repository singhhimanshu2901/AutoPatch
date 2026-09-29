import sqlite3

def query_user_profile(user_input: str) -> list:
    """Fetches user profile by username. Currently vulnerable to SQL Injection."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'superuser'), ('alice', 'member')")

    # Insecure string interpolation flagged by Semgrep (CWE-89)
    query = f"SELECT id, username, role FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
