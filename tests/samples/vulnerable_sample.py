# Vulnerable Python Sample for testing
import os
import subprocess
import sqlite3

AWS_SECRET_KEY = "AKIA1234567890EXAMPLE"

def get_user_profile(user_id):
    # Vulnerability: SQL Injection (CWE-89)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def run_backup(folder_name):
    # Vulnerability: OS Command Injection (CWE-78)
    os.system("tar -czf backup.tar.gz " + folder_name)

def read_config_safe(user_id):
    # Safe: uses parameterization and int casting (JVE should verify or mitigate)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM settings WHERE user_id = ?", (int(user_id),))
    return cursor.fetchone()
