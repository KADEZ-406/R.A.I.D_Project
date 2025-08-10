#!/usr/bin/env python3
"""
SQL Injection Error-Based Test Case
Lab-only vulnerable application for testing SQL injection detection
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# Initialize test database
def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute("INSERT INTO users (username, email, password) VALUES ('admin', 'admin@test.com', 'admin123')")
    cursor.execute("INSERT INTO users (username, email, password) VALUES ('user', 'user@test.com', 'user123')")
    conn.commit()
    return conn

# Global database connection for this lab test
db_conn = init_db()

@app.route('/')
def index():
    return '''
    <h1>SQL Injection Lab Test - Error Based</h1>
    <p>This is a vulnerable endpoint for testing SQL injection detection.</p>
    <p><strong>Test endpoint:</strong> /user?id=1</p>
    <p><strong>Vulnerable parameter:</strong> id</p>
    <p>This endpoint is intentionally vulnerable for testing purposes only.</p>
    '''

@app.route('/user')
def get_user():
    """
    Intentionally vulnerable endpoint that directly concatenates user input
    into SQL query, causing database errors when injection is attempted.
    """
    user_id = request.args.get('id', '1')
    
    try:
        cursor = db_conn.cursor()
        
        # VULNERABLE: Direct string concatenation (DO NOT USE IN PRODUCTION)
        query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
        
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            return jsonify({
                "status": "success",
                "user": {
                    "id": result[0],
                    "username": result[1],
                    "email": result[2]
                }
            })
        else:
            return jsonify({"status": "error", "message": "User not found"}), 404
    
    except sqlite3.Error as e:
        # This will expose database errors when SQL injection is attempted
        return jsonify({
            "status": "error",
            "message": f"Database error: {str(e)}",
            "query_error": "SQLite database error occurred"
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": f"Server error: {str(e)}"
        }), 500

@app.route('/search')
def search_users():
    """
    Another vulnerable endpoint for testing different SQL injection scenarios.
    """
    search_term = request.args.get('q', '')
    
    try:
        cursor = db_conn.cursor()
        
        # VULNERABLE: String concatenation in LIKE clause
        query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        return jsonify({
            "status": "success",
            "results": [{"username": r[0], "email": r[1]} for r in results],
            "count": len(results)
        })
    
    except sqlite3.Error as e:
        return jsonify({
            "status": "error",
            "message": f"Database error: {str(e)}",
            "sqlite_error": "SQLite syntax error"
        }), 500

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "sqli_error_test"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 