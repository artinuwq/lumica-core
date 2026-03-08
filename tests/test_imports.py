import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (ROOT, SRC):
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)


class ImportBoundariesTest(unittest.TestCase):
    def test_runtime_modules_import(self):
        import lumica.runtime.bot  # noqa: F401
        import lumica.runtime.web  # noqa: F401
        import lumica.runtime.worker  # noqa: F401

    def test_lumica_package_boundaries_import(self):
        import lumica.api  # noqa: F401
        import lumica.bot  # noqa: F401
        import lumica.infra  # noqa: F401
        import lumica.integrations  # noqa: F401
        import lumica.jobs  # noqa: F401
        import lumica.runtime  # noqa: F401
        import lumica.services  # noqa: F401


if __name__ == "__main__":
    unittest.main()
