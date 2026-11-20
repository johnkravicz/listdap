"""pytest bootstrap: put the repo root on sys.path so `tests`, `modules` and
`utils` import without installing the package."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
