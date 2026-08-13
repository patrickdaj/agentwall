import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path(tmp_path_factory):
    """Override tmp_path to use a shorter base directory for Unix socket compatibility.

    On macOS, AF_UNIX socket paths are limited to 104 bytes. pytest's default
    tmp_path uses deeply nested directories that exceed this limit.
    This fixture creates temporary paths under /tmp instead.
    """
    base = Path("/tmp/pt")
    base.mkdir(exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="t", dir=str(base)))
    yield tmp_dir
    # Cleanup
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
