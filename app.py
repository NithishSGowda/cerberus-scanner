# app.py
from flask import Flask, render_template, request, send_file
import requests
from urllib.parse import urljoin
import threading
import time
import re
import sys
import os
from report_generator import create_pdf_report
from ai_analyzer import analyze_vulnerabilities_with_ai

# --- Configuration & Wordlist (Copied/Cleaned from original code) ---
# ... (DEFAULT_COMMON_PATHS and DIR_LISTING_PATTERNS remain unchanged) ...
DEFAULT_COMMON_PATHS = [
    '/', '/admin/', '/dashboard/', '/login/', '/panel/', '/setup/',
    '/install/', '/backup/', '/backups/', '/test/', '/dev/', '/old/', '/temp/', '/tmp/',
    '/uploads/', '/files/', '/media/', '/images/', '/css/', '/js/',
    '/config/', '/conf/', '/settings/', '/data/', '/logs/',
    '/error_log', '/access_log', '/debug.log',
    '/README.md', '/LICENSE', '/CHANGELOG.md',
    '/phpinfo.php', '/info.php', '/test.php',
    '/sitemap.xml', '/robots.txt', '/crossdomain.xml', '/security.txt',
    '/.well-known/acme-challenge/', '/.well-known/security.txt',
    '/.env', '/.env.bak', '/.env.old',
    '/.git/config', '/.git/HEAD', '/.git/index',
    '/.svn/entries', '/.svn/wc.db', '/.hg/',
    '/composer.json', '/composer.lock', '/package.json', '/yarn.lock',
    '/node_modules/', '/vendor/', '/.htaccess', '/.htpasswd',
    '/wp-admin/', '/wp-content/', '/wp-includes/',
    '/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/',
    '/joomla/', '/administrator/', '/components/',
    '/drupal/', '/sites/default/files/', '/modules/',
    '/laravel/', '/public/', '/storage/', '/.env',
    '/application/', '/system/', '/app/', '/var/',
    '/assets/', '/cache/',
    'db_backup.sql', 'database.sql', 'backup.sql', 'dump.sql', 'data.sql',
    'site.zip', 'website.zip', 'archive.zip', 'backup.zip', 'web.zip',
    'site.rar', 'website.rar',
    'config.php', 'config.inc.php', 'connections.php', 'db_connect.php',
    'settings.py', 'app_config.yml',
    '/web.config', '/bin/', '/App_Data/', '/App_Code/', '/App_Start/',
    '/_vti_bin/', '/aspnet_client/', '/iisstart.htm',
    '/.dockerignore', '/docker-compose.yml', '/Dockerfile',
    '/kubernetes/', '/serverless.yml',
]

DIR_LISTING_PATTERNS = [
    re.compile(r"<title>Index of /", re.IGNORECASE),
    re.compile(r"Directory listing for /", re.IGNORECASE),
    re.compile(r"Name\s+Last modified\s+Size\s+Description", re.IGNORECASE),
    re.compile(r"<a href=\"\?C=N;O=D\">Name</a>", re.IGNORECASE),
    re.compile(r"<pre>.*?</pre>", re.DOTALL),
    re.compile(r"\[DIR\]", re.IGNORECASE),
]
# --- End Configuration ---

app = Flask(__name__)

# --- NEW: Keep Alive Function for Render Free Tier ---
# This function is started as a background thread to ping the service
# to prevent Render's free tier service from spinning down after 15 min of inactivity.
def keep_alive():
    # Render's free service spins down after 15 minutes (900 seconds)
    PING_INTERVAL = 600 # Ping every 10 minutes (600 seconds)
    
    # Render sets the EXTERNAL_HOSTNAME environment variable to the public URL.
    # We use a non-existent path ('/ping') to avoid hitting the main route logic.
    external_url = os.environ.get("EXTERNAL_HOSTNAME")
    if external_url and not external_url.startswith("http"):
         external_url = f"https://{external_url}" # Force HTTPS for Render

    while external_url:
        try:
            # We ping the root URL to reset the inactivity timer
            requests.get(external_url, timeout=5)
            print(f"[{time.strftime('%H:%M:%S')}] Self-ping successful: {external_url}")
        except requests.exceptions.RequestException as e:
            print(f"[{time.strftime('%H:%M:%S')}] Self-ping failed: {e}")
        
        time.sleep(PING_INTERVAL)


# --- SCANNING CORE FUNCTIONS ---

def run_scan(target_url, num_threads, request_timeout, user_agent, paths_to_check):
    # ... (run_scan logic remains unchanged) ...
    found_exposures = []
    scan_lock = threading.Lock() 

    def check_path_web(target_url, path, user_agent, timeout):
        full_url = urljoin(target_url, path)
        headers = {'User-Agent': user_agent}

        try:
            response = requests.get(full_url, headers=headers, timeout=timeout, allow_redirects=True)
            status_code = response.status_code
            content_type = response.headers.get('Content-Type', '').lower()
            is_directory_listing = False

            if "text/html" in content_type:
                for pattern in DIR_LISTING_PATTERNS:
                    if pattern.search(response.text):
                        is_directory_listing = True
                        break

            # Only report high-interest status codes
            if 200 <= status_code < 300 or status_code == 401 or status_code == 403 or status_code >= 500:
                message = f"Status: {status_code}"
                if is_directory_listing:
                    message += " (Directory Listing Enabled!)"
                elif content_type:
                    message += f" | Content: {content_type.split('/')[-1].upper()}"
                
                with scan_lock:
                    found_exposures.append({
                        'url': full_url,
                        'status_code': status_code,
                        'content_type': content_type,
                        'is_directory_listing': is_directory_listing,
                        'message': message
                    })

        except requests.exceptions.RequestException:
            # Add basic error reporting for the report
            with scan_lock:
                 found_exposures.append({
                    'url': full_url,
                    'status_code': 'N/A',
                    'content_type': 'N/A',
                    'is_directory_listing': False,
                    'message': "Request Failed (Timeout/Connection Error)"
                })


    threads = []
    for path in paths_to_check:
        thread = threading.Thread(target=check_path_web, args=(target_url, path, user_agent, request_timeout))
        threads.append(thread)
        thread.start()

        if len(threads) % num_threads == 0:
            for t in threads[-num_threads:]:
                t.join()
    
    for t in threads:
        t.join()

    return found_exposures


# --- FLASK ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get data from the form
        target_url = request.form['url'].strip()
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        try:
            num_threads = int(request.form.get('threads', 10))
            timeout = int(request.form.get('timeout', 7))
        except ValueError:
            return "Invalid input for threads or timeout.", 400

        # Run the scan
        results = run_scan(
            target_url=target_url,
            num_threads=num_threads,
            request_timeout=timeout,
            user_agent="CerberusScannerWeb/1.0",
            paths_to_check=DEFAULT_COMMON_PATHS
        )
        
        # --- AI ANALYSIS STEP ---
        # Run AI analysis and get the remediation text
        ai_analysis_text = analyze_vulnerabilities_with_ai(results, target_url)
        
        # Generate the PDF report
        report_filename = f"scan_report_{int(time.time())}.pdf"
        report_path = os.path.join(os.getcwd(), report_filename)
        
        # This function call now passes 4 arguments, matching the definition in report_generator.py
        create_pdf_report(results, target_url, report_path, ai_analysis_text)
        
        # Serve the PDF file back to the user
        return send_file(report_path, as_attachment=True)

    return render_template('index.html')

# --- NEW: Background thread to start the keep-alive loop ---
# We use this to check if the app is running via Gunicorn (in production) or Flask's debug server (local).
# This logic is designed to be safe for Gunicorn.
if __name__ == '__main__':
    # Running in debug mode for development
    app.run(debug=True)
else:
    # When running under Gunicorn (production on Render), start the keep-alive thread.
    # Gunicorn workers will use this code.
    print("[INFO] Starting background keep-alive thread...")
    threading.Thread(target=keep_alive, daemon=True).start()
