#!/usr/bin/env python3
# Simple test to check if GUI can be initialized

import os
import sys

# Check if we're in a headless environment
if os.environ.get('DISPLAY') is None and sys.platform != 'win32':
    print("警告: 未找到DISPLAY环境变量，可能无法显示GUI界面")
    print("请确保在图形界面环境中运行此程序")
    sys.exit(1)

try:
    import tkinter as tk
    # Test basic tkinter functionality
    root = tk.Tk()
    root.withdraw()
    root.update()
    root.destroy()
    print("✓ GUI环境测试通过")
except Exception as e:
    print(f"✗ GUI环境测试失败: {e}")
    print("请确保：")
    print("1. 在图形界面环境中运行")
    print("2. Python安装了tkinter支持")
    print("3. 对于Linux，可能需要安装python3-tk包")
    sys.exit(1)

# Test the actual application
print("正在测试TLS工具...")
try:
    sys.argv = [sys.argv[0], "both"]
    from main import main
    main()
except KeyboardInterrupt:
    print("\n程序被用户中断")
    sys.exit(0)
except Exception as e:
    print(f"程序运行错误: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)