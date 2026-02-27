"""conftest.py — adds project root to sys.path so tests work on a fresh clone."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
