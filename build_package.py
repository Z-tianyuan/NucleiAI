"""构建可分发 Windows 包（免 Python 运行）。

产出：
- dist/NucleiAI/NucleiAI.exe           Web 面板（自动打开浏览器）
- dist/NucleiAI/NucleiAI-Target.exe    本地漏洞靶场
- dist/NucleiAI/nuclei.exe, httpx.exe  扫描器二进制
- dist/NucleiAI-windows-x64.zip        最终分发包

用法：python build_package.py
说明：nuclei/httpx 二进制从 ~/bin 拷贝，可用环境变量 NUCLEIAI_BIN_DIR 指定目录。
"""

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist" / "NucleiAI"
PY = sys.executable


def run(cmd: list) -> None:
    print("$", " ".join(str(c) for c in cmd))
    subprocess.run([str(c) for c in cmd], cwd=ROOT, check=True)


def main() -> None:
    shutil.rmtree(DIST_DIR, ignore_errors=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # conda 版 Python 的 DLL 依赖，需显式打进 exe（否则 _ssl/lzma/bz2 等加载失败）
    conda_bin = Path(os.environ.get("CONDA_PREFIX", "")) / "Library" / "bin"
    if not conda_bin.exists():
        conda_bin = Path(r"E:\anaconda3\Library\bin")
    required_dlls = [
        "libssl-3-x64.dll", "libcrypto-3-x64.dll", "liblzma.dll", "LIBBZ2.dll",
        "libmpdec-4.dll", "libexpat.dll", "ffi.dll", "zlib.dll",
        "concrt140.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll",
    ]
    add_binary = []
    for dll in required_dlls:
        src = conda_bin / dll
        if src.exists():
            add_binary += ["--add-binary", f"{src}{os.pathsep}."]
            print(f"[+] 打包 DLL: {dll}")
        else:
            print(f"[!] 未找到 DLL: {dll}")

    # 1. Web 面板
    run([
        PY, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onefile", "--name", "NucleiAI",
        "--add-data", f"web/templates{os.pathsep}web/templates",
        "--add-data", f"custom-templates{os.pathsep}custom-templates",
        "--add-data", f"config.yaml{os.pathsep}.",
        "--paths", str(ROOT),
        "--hidden-import", "python_multipart",
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.lifespan.on",
        *add_binary,
        "serve.py",
    ])

    # 2. 本地漏洞靶场
    run([
        PY, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onefile", "--name", "NucleiAI-Target",
        "--paths", str(ROOT),
        "--paths", str(ROOT / "test-target"),
        "target_server.py",
    ])

    # 3. 组装分发目录
    for name in ("NucleiAI.exe", "NucleiAI-Target.exe"):
        shutil.copy(ROOT / "dist" / name, DIST_DIR / name)

    bin_dir = Path(os.environ.get("NUCLEIAI_BIN_DIR", Path.home() / "bin"))
    for name in ("nuclei.exe", "httpx.exe"):
        src = bin_dir / name
        if src.exists():
            shutil.copy(src, DIST_DIR / name)
            print(f"[+] 已拷贝 {name}")
        else:
            print(f"[!] 未找到 {name}，请从 ProjectDiscovery Releases 下载后放入分发目录")

    shutil.copy(ROOT / "README.md", DIST_DIR / "README.md")
    (DIST_DIR / "使用说明.txt").write_text(
        "NucleiAI 免安装运行包（Windows x64）\n"
        "====================================\n\n"
        "快速开始：\n"
        "  1. 双击 NucleiAI-Target.exe 启动本地漏洞靶场（127.0.0.1:9999）\n"
        "  2. 双击 NucleiAI.exe 启动 Web 面板，会自动打开浏览器\n"
        "  3. 在扫描框输入 http://127.0.0.1:9999 即可测试\n\n"
        "AI 功能（可选，二选一）：\n"
        "  A. 云 API（推荐，无需额外安装）：设置环境变量后重启 NucleiAI.exe\n"
        "     set NUCLEIAI_LLM_API_KEY=你的Key\n"
        "     set NUCLEIAI_LLM_BASE_URL=https://api.deepseek.com/v1\n"
        "     set NUCLEIAI_LLM_MODEL=deepseek-chat\n"
        "  B. 本地 Ollama：安装 Ollama 并 ollama pull qwen3:8b，保持默认配置即可\n"
        "  C. 不配置也能用：扫描照常进行，AI 无法判定的结果会标记为「待人工复核」\n\n"
        "面板访问令牌（可选）：\n"
        "  set NUCLEIAI_AUTH_TOKEN=你的令牌\n\n"
        "数据目录：\n"
        "  会话等可写数据保存在本目录 data/ 下，删除即重置\n"
        "  如需覆盖配置，在 data/ 放一个 config.local.yaml（格式参考项目 config.local.yaml.example）\n\n"
        "社区模板（可选）：\n"
        "  将 nuclei-templates 目录放到本目录（或 data/）下，面板即可启用社区模板扫描\n\n"
        "说明：仅用于授权安全测试。",
        encoding="utf-8",
    )

    # 4. 压缩
    zip_path = ROOT / "dist" / "NucleiAI-windows-x64.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(DIST_DIR.rglob("*")):
            zf.write(f, f.relative_to(DIST_DIR.parent))

    print(f"\n[+] 完成: {zip_path}")
    print(f"[+] 大小: {zip_path.stat().st_size / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
