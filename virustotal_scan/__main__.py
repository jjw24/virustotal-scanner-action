"""Allow ``python -m virustotal_scan`` as an entry point."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from virustotal_scan.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
