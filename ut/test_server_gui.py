#!/usr/bin/env python3
# Simple test to run the application with GUI

import sys
from main import main

if __name__ == "__main__":
    # Set command line arguments for server mode
    sys.argv = [sys.argv[0], "server"]
    try:
        main()
    except Exception as e:
        print(f"Error running main(): {e}")
        import traceback
        traceback.print_exc()