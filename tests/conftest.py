"""Test helpers.

Every cipher folder contains a file literally named encrypt.py / decrypt.py /
hash.py, so a plain `import encrypt` can only ever see one of them. load()
imports a module by *path* under a unique name so the tests can hold several
ciphers at once.
"""
import importlib.util
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src')
SRC = os.path.abspath(SRC)
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def load(rel_path):
    """Import `src/<rel_path>` (e.g. 'substitution/caesar/encrypt.py')."""
    full = os.path.join(SRC, rel_path)
    name = 'crypto_ex_' + rel_path.replace('/', '_').replace('.py', '')
    spec = importlib.util.spec_from_file_location(name, full)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def load_module():
    return load


@pytest.fixture
def opts():
    """Build the pandas option frame the classes expect: opts(OFFSET=3)."""
    import pandas as pd

    def _make(**kw):
        return pd.DataFrame({k: [v] for k, v in kw.items()})
    return _make
