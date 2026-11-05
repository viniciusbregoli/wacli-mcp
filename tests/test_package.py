import tomllib
from pathlib import Path

import wacli_mcp


def test_version_matches_pyproject():
    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert wacli_mcp.__version__ == pyproject["project"]["version"]
