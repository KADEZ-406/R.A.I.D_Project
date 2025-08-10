#!/usr/bin/env python3
"""
Reflected XSS Test Case
Lab-only vulnerable application for testing XSS detection
"""

from flask import Flask, request, render_template_string
import html

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>XSS Lab Test - Reflected</h1>
    <p>This is a vulnerable endpoint for testing XSS detection.</p>
    <p><strong>Test endpoints:</strong></p>
    <ul>
        <li>/search?q=test</li>
        <li>/welcome?name=user</li>
        <li>/comment?message=hello</li>
    </ul>
    <p>These endpoints are intentionally vulnerable for testing purposes only.</p>
    '''

@app.route('/search')
def search():
    """
    Vulnerable search endpoint that reflects user input without proper encoding.
    """
    query = request.args.get('q', '')
    
    # VULNERABLE: Direct reflection without encoding
    html_template = f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <div id="results">
            <p>No results found for your search.</p>
        </div>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    
    return html_template

@app.route('/welcome')
def welcome():
    """
    Vulnerable welcome endpoint that reflects name parameter.
    """
    name = request.args.get('name', 'Guest')
    
    # VULNERABLE: Reflection in JavaScript context
    html_template = f'''
    <html>
    <head><title>Welcome</title></head>
    <body>
        <h1>Welcome, {name}!</h1>
        <script>
            var username = "{name}";
            console.log("Welcome " + username);
        </script>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    
    return html_template

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    """
    Vulnerable comment endpoint that reflects user input.
    """
    if request.method == 'POST':
        message = request.form.get('message', '')
    else:
        message = request.args.get('message', '')
    
    # VULNERABLE: Direct reflection in HTML attribute
    html_template = f'''
    <html>
    <head><title>Comment</title></head>
    <body>
        <h1>Your Comment</h1>
        <div class="comment" data-message="{message}">
            <p>Comment: {message}</p>
        </div>
        <form method="post">
            <input type="text" name="message" placeholder="Enter comment">
            <button type="submit">Submit</button>
        </form>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    
    return html_template

@app.route('/safe_search')
def safe_search():
    """
    Safe version for comparison - properly encodes user input.
    """
    query = request.args.get('q', '')
    
    # SAFE: Proper HTML encoding
    safe_query = html.escape(query)
    
    html_template = f'''
    <html>
    <head><title>Safe Search Results</title></head>
    <body>
        <h1>Safe Search Results</h1>
        <p>You searched for: {safe_query}</p>
        <div id="results">
            <p>No results found for your search.</p>
        </div>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    
    return html_template

@app.route('/profile')
def profile():
    """
    Vulnerable profile endpoint with multiple reflection points.
    """
    name = request.args.get('name', '')
    bio = request.args.get('bio', '')
    website = request.args.get('website', '')
    
    # VULNERABLE: Multiple reflection contexts
    html_template = f'''
    <html>
    <head>
        <title>Profile: {name}</title>
        <meta name="description" content="Profile of {name}">
    </head>
    <body>
        <h1>{name}'s Profile</h1>
        <div class="profile">
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Bio:</strong> {bio}</p>
            <p><strong>Website:</strong> <a href="{website}">{website}</a></p>
        </div>
        <script>
            document.title = "Profile: {name}";
            var userBio = "{bio}";
        </script>
        <a href="/">Back to home</a>
    </body>
    </html>
    '''
    
    return html_template

@app.route('/health')
def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "xss_reflected_test"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True) 