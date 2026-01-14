#!/bin/bash
# IPv4/IPv6 TLS工具启动器 (Unix/Linux/macOS版本)
# 支持参数: client|server|both [配置文件路径]

echo "========================================"
echo "IPv4/IPv6 TLS工具集启动器"
echo "========================================"
echo

MODE="both"
CONFIG_FILE="tls_config.json"

# 解析命令行参数
if [ $# -gt 0 ]; then
    case "$1" in
        client|server|both)
            MODE="$1"
            ;;
        *)
            echo "错误: 无效的模式 '$1'. 使用: client|server|both"
            exit 1
            ;;
    esac
fi

if [ $# -gt 1 ]; then
    CONFIG_FILE="$2"
fi

echo "启动模式: $MODE"
echo "配置文件: $CONFIG_FILE"
echo

# 检查Python是否可用
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "错误: 未找到Python，请确保Python已安装并添加到PATH"
    exit 1
fi

# 检查主程序文件是否存在
if [ ! -f "main.py" ]; then
    echo "错误: 未找到main.py文件"
    exit 1
fi

echo "正在启动TLS工具..."
$PYTHON_CMD main.py "$MODE" "$CONFIG_FILE"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo
    echo "启动失败，退出码: $EXIT_CODE"
    echo "请检查上面的错误信息"
    read -p "按回车键退出..."
fi