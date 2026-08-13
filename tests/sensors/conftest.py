import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path():
    """Override tmp_path with a short base directory for Unix socket compatibility.

    On macOS, AF_UNIX socket paths are limited to 104 bytes. pytest's default
    tmp_path uses deeply nested directories that exceed this limit for the
    AF_UNIX socket tests in this subpackage. Scoped to tests/sensors/ only.
    """
    base = Path("/tmp/pt")
    base.mkdir(exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="t", dir=str(base)))
    yield tmp_dir
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
