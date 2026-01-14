#!/usr/bin/env python3
# Test script to check the application modes

import sys
import tkinter as tk
from main import TLSToolApplication

def test_mode(mode):
    print(f"Testing {mode} mode...")
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the window for testing
        app = TLSToolApplication(root, mode)
        print(f"✓ {mode} mode initialized successfully")
        root.destroy()
        return True
    except Exception as e:
        print(f"✗ {mode} mode failed: {e}")
        return False

if __name__ == "__main__":
    modes = ["client", "server", "both"]
    success = True
    
    for mode in modes:
        if not test_mode(mode):
            success = False
    
    if success:
        print("\n✓ All modes working correctly!")
    else:
        print("\n✗ Some modes have issues")
        sys.exit(1)