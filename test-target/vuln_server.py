"""Intentionally vulnerable web server — for testing NucleiAI detection pipeline.

Real vulnerabilities (14 endpoints):
  1.  Reflected XSS via /search?q=<script>...
  2.  Open Redirect via /redirect?url=...
  3.  Debug endpoint exposure at /debug
  4.  Admin panel exposure at /admin
  5.  .git directory exposure at /.git/
  6.  Stack trace leak at /error
  7.  Credentials in comments at /login
  8.  Server version disclosure (response header)
  9.  SQL injection error at /api/users?id=1'
  10. SSRF at /fetch?url=...
  11. Directory listing at /files/
  12. CORS misconfiguration at /api/data
  13. Missing security headers (all pages)
  14. Sensitive file exposure at /backup/

False positive traps (6 endpoints):
  15. /blog/xss-tutorial   — security article containing <script> in code examples
  16. /about               — page mentioning "git" and ".git" in text
  17. /goto?url=/home      — redirect with domain whitelist
  18. /safe-search?q=xss   — search with proper HTML escaping
  19. /status              — debug info says "Debug Mode: OFF"
  20. /oops                — generic 500 error without stack trace

DO NOT expose this server to any network. Local testing only.
"""
import json
import os
import re
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path


class VulnHandler(SimpleHTTPRequestHandler):
    """Handler with intentional vulnerabilities."""

    server_version = "Apache/2.4.57 (Debian)"
    sys_version = ""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # === 1. Reflected XSS ===
        if path == "/search":
            query = params.get("q", [""])[0]
            self._html_response(200, f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Search Results</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: {query}</p>
    <p>No results found.</p>
</body>
</html>""")

        # === 2. Open Redirect ===
        elif path == "/redirect":
            target = params.get("url", [""])[0]
            if target:
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
            else:
                self._html_response(400, "<h1>Missing 'url' parameter</h1>")

        # === 3. Exposed Debug Endpoint ===
        elif path == "/debug":
            info = {
                "python_version": sys.version,
                "cwd": os.getcwd(),
                "env_vars": {k: v for k, v in os.environ.items()
                             if k in ("PATH", "USERNAME", "COMPUTERNAME", "TEMP", "HOMEDRIVE")},
                "pid": os.getpid(),
            }
            self._html_response(200, f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Debug Info</title></head>
<body>
    <h1>Server Debug Information</h1>
    <pre>{json.dumps(info, indent=2, ensure_ascii=False)}</pre>
</body>
</html>""")

        # === 4. Admin panel (fake, but exposed) ===
        elif path == "/admin":
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Panel</h1>
    <form method="post" action="/admin">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    <p style="color:gray;font-size:12px;">Default credentials: admin / admin123</p>
</body>
</html>""")

        # === 5. Exposed .git directory ===
        elif path.startswith("/.git"):
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>.git</title></head>
<body>
    <h1>Index of /.git</h1>
    <ul>
        <li><a href="/.git/config">config</a></li>
        <li><a href="/.git/HEAD">HEAD</a></li>
        <li><a href="/.git/logs/">logs/</a></li>
    </ul>
</body>
</html>""")

        # === 6. robots.txt with sensitive paths ===
        elif path == "/robots.txt":
            self._text_response(200, """User-agent: *
Disallow: /admin
Disallow: /debug
Disallow: /backup
Disallow: /.git""")

        # === 7. Error page with stack trace (simulated) ===
        elif path == "/error":
            self._html_response(500, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Internal Server Error</title></head>
<body>
    <h1>500 Internal Server Error</h1>
    <pre style="background:#fee;padding:8px;overflow:auto;">
Traceback (most recent call last):
  File "app.py", line 42, in handle_request
    result = db.execute("SELECT * FROM users WHERE id=" + user_id)
DatabaseError: connection refused at 127.0.0.1:5432
    </pre>
</body>
</html>""")

        # === 8. FALSE POSITIVE: Security blog tutorial (triggers XSS keywords) ===
        elif path == "/blog/xss-tutorial":
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>XSS 安全教程 - Demo Corp Blog</title></head>
<body>
    <article>
        <h1>跨站脚本攻击 (XSS) 入门教程</h1>
        <p>跨站脚本攻击是一种常见的 Web 安全漏洞。攻击者通常会在输入框中注入恶意脚本。</p>
        <h2>漏洞示例</h2>
        <p>以下是一段存在 XSS 漏洞的危险代码（请勿在生产环境使用）：</p>
        <pre><code>&lt;p&gt;Search results for: {{ user_input }}&lt;/p&gt;</code></pre>
        <p>当用户输入为 <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> 时，实际响应为：</p>
        <pre><code>&lt;p&gt;Search results for: <script>alert('XSS')</script>&lt;/p&gt;</code></pre>
        <p>注意：上方代码块中包含了真实的脚本标签，如看到弹窗说明浏览器执行了该脚本。</p>
        <p>防御方法：对用户输入进行 HTML 实体编码，如使用 <code>html.escape()</code>。</p>
    </article>
</body>
</html>""")

        # === 9. FALSE POSITIVE: About page mentioning git (triggers .git exposure) ===
        elif path == "/about":
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>About Us - Demo Corp</title></head>
<body>
    <h1>About Demo Corp</h1>
    <p>我们是一个专注于安全研究的团队。</p>
    <h2>开发流程</h2>
    <ul>
        <li>项目代码使用 git 进行版本管理</li>
        <li>代码托管在内部 GitLab 服务器</li>
        <li>CI/CD 通过 GitHub Actions 实现</li>
        <li>用浏览器访问 Index of /.git 可查看仓库文件列表</li>
    </ul>
    <p>联系我们：admin@demo-corp.internal</p>
</body>
</html>""")

        # === 10. FALSE POSITIVE: Safe redirect (domain-restricted, always internal) ===
        elif path == "/goto":
            target = params.get("url", [""])[0]
            # Always redirect to a safe internal page, regardless of input
            safe_url = "/error?msg=external_url_blocked_by_whitelist"
            self.send_response(302)
            self.send_header("Location", safe_url)
            self.end_headers()

        # === 11. FALSE POSITIVE: Safe search with HTML escaping ===
        elif path == "/safe-search":
            import html
            query = params.get("q", [""])[0]
            safe_query = html.escape(query)
            self._html_response(200, f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Safe Search</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: {safe_query}</p>
    <p>No results found. (input was HTML-escaped)</p>
    <!-- dev-note: the raw query param was "<script>alert('XSS')</script>" - see server logs for details -->
</body>
</html>""")

        # === 12. FALSE POSITIVE: Status page (fake debug info) ===
        elif path == "/status":
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>System Status</title></head>
<body>
    <h1>System Status</h1>
    <pre>
Server Status: Running
Debug Mode: OFF
Debug Information: not available in production
python_version: redacted
Last Check: 2026-05-20 15:30:00
    </pre>
    <p style="color:green;">All systems operational.</p>
</body>
</html>""")

        # === 13. FALSE POSITIVE: Generic error page (no sensitive info) ===
        elif path == "/oops":
            self._html_response(500, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Error</title></head>
<body>
    <h1>500 — Something went wrong</h1>
    <p>We're sorry, an unexpected error occurred. Please try again later.</p>
    <p style="color:#666;font-size:12px;">
        If you encounter a Traceback or DatabaseError, please contact the admin.
        All error details have been redacted from this page for security.
    </p>
</body>
</html>""")

        # === 14. Normal pages ===
        elif path == "/" or path == "/index.html":
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Welcome - Demo Corp</title></head>
<body>
    <h1>Welcome to Demo Corp</h1>
    <p>Internal portal for employee use.</p>
    <ul>
        <li><a href="/search?q=test">Search</a></li>
        <li><a href="/admin">Admin Panel</a></li>
        <li><a href="/blog/xss-tutorial">Blog: XSS Tutorial</a></li>
        <li><a href="/about">About Us</a></li>
        <li><a href="/status">System Status</a></li>
    </ul>
</body>
</html>""")

        # === 9. Login page with insecure message ===
        elif path == "/login":
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    <form method="post" action="/login">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <button type="submit">Login</button>
    </form>
    <!-- TODO: remove after testing -->
    <!-- test credentials: admin / admin123 -->
</body>
</html>""")

        # === 9. SQL Injection error ===
        elif path == "/api/users":
            user_id = params.get("id", [""])[0]
            if "'" in user_id or "OR" in user_id.upper():
                self._html_response(500, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Database Error</title></head>
<body>
    <h1>Database Error</h1>
    <pre style="background:#fee;padding:8px;">
SQLSTATE[42000]: Syntax error or access violation: 1064
You have an error in your SQL syntax; check the manual that corresponds to
your MySQL server version for the right syntax to use near
'OR 1=1 --' at line 1

Query: SELECT id, username, email FROM users WHERE id = '1' OR 1=1 --'
                                                         ^
    </pre>
</body>
</html>""")
            else:
                self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>User Info</title></head>
<body>
    <h1>User Profile</h1>
    <p>ID: 1 | Username: admin | Email: admin@demo-corp.internal</p>
</body>
</html>""")

        # === 10. SSRF endpoint ===
        elif path == "/fetch":
            target = params.get("url", [""])[0]
            if target:
                self._html_response(200, f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Fetch Result</title></head>
<body>
    <h1>URL Fetcher</h1>
    <p>Fetching: {target}</p>
    <pre>Response from {target}:
HTTP/1.1 200 OK
Content-Type: application/json

{{"internal_data": "secret_api_key_12345", "users": [...]}}
    </pre>
</body>
</html>""")
            else:
                self._html_response(400, "<h1>Missing 'url' parameter</h1>")

        # === 11. Directory listing ===
        elif path == "/files/" or path == "/files":
            self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Index of /files/</title></head>
<body>
    <h1>Index of /files/</h1>
    <table>
        <tr><th>Name</th><th>Size</th><th>Modified</th></tr>
        <tr><td><a href="/files/">../</a></td><td>-</td><td></td></tr>
        <tr><td><a href="/files/database.sql">database.sql</a></td><td>2.3 MB</td><td>2026-05-20</td></tr>
        <tr><td><a href="/files/backup.tar.gz">backup.tar.gz</a></td><td>45 MB</td><td>2026-05-19</td></tr>
        <tr><td><a href="/files/config.ini">config.ini</a></td><td>1.2 KB</td><td>2026-05-18</td></tr>
        <tr><td><a href="/files/employees.xlsx">employees.xlsx</a></td><td>856 KB</td><td>2026-05-15</td></tr>
    </table>
</body>
</html>""")

        # === 12. CORS misconfiguration ===
        elif path == "/api/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b'{"users":[{"id":1,"name":"admin","role":"superuser"},{"id":2,"name":"alice","role":"user"}],"total":2}')

        # === 13. Sensitive file exposure (backup directory) ===
        elif path.startswith("/backup"):
            if path == "/backup/" or path == "/backup":
                self._html_response(200, """<!DOCTYPE html>
<html lang="zh-CN">
<head><title>Index of /backup/</title></head>
<body>
    <h1>Index of /backup/</h1>
    <ul>
        <li><a href="/backup/db_dump_20260520.sql">db_dump_20260520.sql</a> (12.4 MB)</li>
        <li><a href="/backup/config.php.bak">config.php.bak</a> (3.2 KB)</li>
        <li><a href="/backup/.env.production">.env.production</a> (1.8 KB)</li>
        <li><a href="/backup/users.csv">users.csv</a> (256 KB)</li>
    </ul>
</body>
</html>""")
            elif path == "/backup/.env.production":
                self._text_response(200, """DB_HOST=prod-db.internal
DB_PORT=5432
DB_NAME=corp_production
DB_USER=admin
DB_PASS=SuperSecret123!
SECRET_KEY=prod-secret-key-do-not-share
API_TOKEN=sk-prod-abc123def456""")

        else:
            super().do_GET()

    def _html_response(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", self.server_version)
        self.send_header("X-Powered-By", "PHP/7.4.33")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _text_response(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Quiet logging


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"Vulnerable test server at http://127.0.0.1:{port}")
    print("Endpoints: 14 vulns + 6 false-positive traps = 20 total")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
