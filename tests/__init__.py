"""Test suite. Run from the repository root:

    python -m unittest discover -s tests -t . -v

The tests never touch your real data: everything is written to a temporary folder.
"""

import os
import tempfile

# Must happen before anything imports mapper.common, which reads these at import time.
_SANDBOX = tempfile.mkdtemp(prefix="computer-mapper-tests-")
os.environ["MAPPER_DATA_DIR"] = os.path.join(_SANDBOX, "data")
os.environ["MAPPER_REPORT_DIR"] = os.path.join(_SANDBOX, "reports")
