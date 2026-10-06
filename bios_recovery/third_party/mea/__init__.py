# ME Analyzer integration for BIOS Recovery Suite
# Bundled copy of ME Analyzer (https://github.com/platomav/MEAnalyzer)
# Licensed under BSD permissive license
__all__ = ["MEA_PATH", "DATA_FILES"]

import os

MEA_ROOT = os.path.dirname(os.path.abspath(__file__))
MEA_PATH = os.path.join(MEA_ROOT, "MEA.py")
DATA_FILES = [
    os.path.join(MEA_ROOT, "MEA.dat"),
    os.path.join(MEA_ROOT, "Huffman.dat"),
    os.path.join(MEA_ROOT, "FileTable.dat"),
]

def ensure_data_files():
    """Ensure ME Analyzer data files exist."""
    return all(os.path.exists(f) for f in DATA_FILES)
