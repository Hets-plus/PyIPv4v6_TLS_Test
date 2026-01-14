@echo off
REM IPv4/IPv6 TLS工具启动器
REM 支持参数: client|server|both [配置文件路径]
REM Windows服务安装请使用: tls_windows_service.ps1

echo ========================================
echo IPv4/IPv6 TLS工具集启动器
echo ========================================
echo.
echo 使用方法:
echo   %0 client        - 仅启动客户端模式
echo   %0 server        - 仅启动服务器模式  
echo   %0 both          - 启动客户端和服务器模式 (默认)
echo   %0 both config.json - 使用指定配置文件
echo.
echo Windows服务安装:
echo   powershell -NoProfile -ExecutionPolicy Bypass -File tls_windows_service.ps1 -Action install -Mode server -Config tls_config.json
echo.

set MODE=both
set CONFIG_FILE=tls_config.json

REM 解析命令行参数
if "%1"=="" goto :start
if /i "%1"=="client" set MODE=client
if /i "%1"=="server" set MODE=server
if /i "%1"=="both" set MODE=both
if not "%2"=="" set CONFIG_FILE=%2

:start
echo 启动模式: %MODE%
echo 配置文件: %CONFIG_FILE%
echo.

REM 切换到脚本所在目录，避免工作目录导致相对路径异常
cd /d "%~dp0"

REM 检查Python是否可用
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请确保Python已安装并添加到PATH
    pause
    exit /b 1
)

REM 检查主程序文件是否存在
if not exist "main.py" (
    echo 错误: 未找到main.py文件
    pause
    exit /b 1
)

echo 正在启动TLS工具...
python main.py %MODE% %CONFIG_FILE%

if errorlevel 1 (
    echo.
    echo 启动失败，请检查错误信息
    pause
)
exit /b 0
