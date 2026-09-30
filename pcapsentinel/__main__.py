"""Executable entry point when running `python -m pcapsentinel`."""

import sys
from pcapsentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
