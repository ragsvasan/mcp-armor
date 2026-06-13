"""B5 — smoke test that the benchmark harness stays runnable.

This does NOT assert on timing (perf is machine-dependent and flaky in CI); it
just drives a few iterations of the full chain so benchmarks/chain_overhead.py
cannot silently rot. Run the real numbers with:
    python benchmarks/chain_overhead.py 20000
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parent.parent / "benchmarks" / "chain_overhead.py"


@pytest.mark.asyncio
async def test_benchmark_harness_runs() -> None:
    spec = importlib.util.spec_from_file_location("chain_overhead", _BENCH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["chain_overhead"] = mod
    spec.loader.exec_module(mod)
    # A handful of iterations through both chains — proves the harness builds the
    # guard, mints a token, and drives request+response without error.
    await mod._bench(50, include_audit=False)
    await mod._bench(50, include_audit=True)
