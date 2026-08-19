@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================
echo   NucleiAI - AI 增强漏洞管理平台 启动器
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] 未找到 Python，请先安装 Python 3.11+ 并加入 PATH
    pause
    exit /b 1
)

python -c "import fastapi, httpx, yaml, bs4, lxml" >nul 2>nul
if errorlevel 1 (
    echo [*] 首次运行，安装依赖...
    python -m pip install -r requirements.txt || (echo [ERROR] 依赖安装失败 & pause & exit /b 1)
)

echo [*] 检查环境...
python run.py check

echo.
echo [*] 启动本地漏洞靶场 (127.0.0.1:9999)...
start "NucleiAI Test Target" /min cmd /c "cd /d %~dp0 && python test-target\vuln_server.py 9999"

echo [*] 启动 Web 面板...
echo     浏览器打开 http://127.0.0.1:8080
python run.py

endlocal
