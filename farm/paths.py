"""Shared checkout root; never modifies Python import search paths."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
