"""Offline CI-equivalent gate: everything a merge check would run, no network.

    python tools/check.py            # run every gate, report at the end
    python tools/check.py --fast     # skip the branch-coverage run (reuse plain pytest)

Gates, in order:
  1. ruff          lint (src + tests + tools + examples + mutmut_config.py)
  2. mypy          type check (src and examples, the typed surface)
  3. pytest        deterministic suite under branch coverage, fail_under from pyproject
  4. properties    the Hypothesis property and model-based lifecycle tests (kept out of
                   the coverage measure)
  5. matrix        conformance matrix is not stale  (tools/extract_matrix.py --check)
  6. adversarial   adversarial results are not stale (tools/run_adversarial.py --check)

Exit code is non-zero if any gate fails. Run it before opening a pull request; it
needs no outbound network and no second implementation.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Prefer the project venv's interpreter so the gate uses the pinned toolchain.
_WIN = sys.platform.startswith("win")
_VENV = ROOT / ".venv" / ("Scripts" if _WIN else "bin") / ("python.exe" if _WIN else "python")
PY = str(_VENV) if _VENV.exists() else sys.executable


def run(name: str, argv: list[str]) -> bool:
    print(f"\n=== {name} ===", flush=True)
    proc = subprocess.run(argv, cwd=ROOT)
    ok = proc.returncode == 0
    print(f"--- {name}: {'OK' if ok else 'FAIL'} (exit {proc.returncode}) ---", flush=True)
    return ok


def main() -> int:
    fast = "--fast" in sys.argv
    results: list[tuple[str, bool]] = []

    results.append(("ruff", run("ruff", [PY, "-m", "ruff", "check", "src", "tests", "tools", "examples",
                                         "mutmut_config.py"])))
    results.append(("mypy", run("mypy", [PY, "-m", "mypy", "src", "examples"])))

    if fast:
        results.append(("pytest", run("pytest", [PY, "-m", "pytest", "-q"])))
    else:
        # Coverage is measured on the deterministic suite only, so 100% never depends on
        # what Hypothesis happened to draw; the property tests then run as their own gate.
        cov_ok = run("pytest+coverage", [PY, "-m", "coverage", "run", "-m", "pytest", "-q",
                                         "--ignore=tests/test_properties.py",
                                         "--ignore=tests/test_properties_lifecycle.py",
                                         "--ignore=tests/test_properties_open_acts.py",
                                         "--ignore=tests/test_properties_cross_mission.py",
                                         "--ignore=tests/test_properties_markdown.py"])
        if cov_ok:
            cov_ok = run("coverage report", [PY, "-m", "coverage", "report"])
        results.append(("pytest+coverage", cov_ok))
        results.append(("properties", run("properties", [
            PY, "-m", "pytest", "-q", "tests/test_properties.py",
            "tests/test_properties_lifecycle.py", "tests/test_properties_open_acts.py",
            "tests/test_properties_cross_mission.py", "tests/test_properties_markdown.py"])))

    results.append(("matrix", run("matrix", [PY, "tools/extract_matrix.py", "--check"])))
    results.append(("adversarial", run("adversarial", [PY, "tools/run_adversarial.py", "--check"])))

    print("\n==================== SUMMARY ====================")
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    all_ok = all(ok for _, ok in results)
    print("================================================")
    print("ALL GATES GREEN" if all_ok else "ONE OR MORE GATES FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
