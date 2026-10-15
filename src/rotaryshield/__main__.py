"""Run the daemon with the same arguments and exit status as the console script."""
import sys
from .main import main

if __name__ == "__main__":
    sys.exit(main())
