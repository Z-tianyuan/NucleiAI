"""打包版入口：启动 Web 面板并自动打开浏览器。

用法：NucleiAI.exe   或   python serve.py
"""

import threading
import webbrowser

import uvicorn

from core.config import get_config
from web.app import app


def _open_browser(host: str, port: int) -> None:
    try:
        webbrowser.open(f"http://{host}:{port}")
    except Exception:
        pass


if __name__ == "__main__":
    cfg = get_config()
    host, port = cfg["server_host"], cfg["server_port"]
    threading.Timer(1.2, _open_browser, args=(host, port)).start()
    print(f"NucleiAI 面板: http://{host}:{port}  (Ctrl+C 退出)")
    uvicorn.run(app, host=host, port=port, reload=False)
