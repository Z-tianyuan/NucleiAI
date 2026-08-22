"""打包版测试靶场入口：监听 127.0.0.1:9999。

用法：NucleiAI-Target.exe   或   python target_server.py [port]
"""

import sys
from http.server import HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "test-target"))

from vuln_server import VulnHandler  # noqa: E402


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"漏洞测试靶场: http://127.0.0.1:{port}  (Ctrl+C 退出)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
