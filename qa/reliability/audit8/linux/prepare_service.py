#!/usr/bin/env python3
"""Qualification entry for the single shipped Linux service installer."""
from pathlib import Path
import runpy

if __name__ == "__main__":
    installer = Path(__file__).resolve().parents[4] / "source/.knowledge/tools/install-linux-native-service.py"
    runpy.run_path(str(installer), run_name="__main__")
