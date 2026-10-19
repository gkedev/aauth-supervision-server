"""Re-verify mutmut survivors against the full suite, independently of mutmut's bookkeeping.

    python tools/mutation_recheck.py src/aauth_supervision_server/service.py          # every survivor
    python tools/mutation_recheck.py src/aauth_supervision_server/service.py 28 144   # chosen ids

Run it in the tree mutmut ran in (it reads `.mutmut-cache`), after `mutmut run`. For each
mutant mutmut did not record as killed, it applies the mutant, deletes the bytecode
caches, runs the whole suite with bytecode writing off, and restores the source. A mutant
counts as killed only if pytest fails here; the unmutated suite must pass first, or every
mutant would look killed.

Why: on Windows, mutmut 2.5.1 recorded mutants as survived that the suite does kill when
the mutant is applied by hand (docs/mutation-testing.md). The survivors reported in the
docs are the ones this script confirms.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()


def pytest(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    for top in ("src", "tests"):
        for pyc in (ROOT / top).rglob("__pycache__"):
            shutil.rmtree(pyc, ignore_errors=True)
    # The Hypothesis properties are left out: a mutant counts as killed only by a test
    # that kills it on every run, never by an input one run happened to draw.
    return subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", "-x",
                           "-p", "no:cacheprovider", "--ignore=tests/test_properties.py",
                           "--ignore=tests/test_properties_lifecycle.py",
                           "--ignore=tests/test_properties_open_acts.py",
                           "--ignore=tests/test_properties_cross_mission.py",
                           "--ignore=tests/test_properties_markdown.py", "tests"],
                          cwd=ROOT, capture_output=True, text=True, env=env)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    target = ROOT / sys.argv[1]
    ids = sys.argv[2:]
    if not ids:
        db = sqlite3.connect(ROOT / ".mutmut-cache")
        ids = [str(r[0]) for r in db.execute(
            "select m.id from Mutant m join Line l on m.line = l.id "
            "join SourceFile s on l.sourcefile = s.id "
            "where m.status != 'ok_killed' and s.filename = ?",
            (sys.argv[1].replace("\\", "/"),))]
    pristine = target.read_bytes()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    base = pytest(env)
    if base.returncode != 0:
        print("the unmutated suite fails; fix it first\n" + base.stdout[-2000:])
        return 2
    survived = []
    try:
        for i in ids:
            target.write_bytes(pristine)
            subprocess.run([sys.executable, "-m", "mutmut", "apply", i], cwd=ROOT,
                           capture_output=True, check=True)
            if target.read_bytes() == pristine:
                print(f"#{i}: mutmut applied no change")
                continue
            r = pytest(env)
            verdict = "killed" if r.returncode != 0 else "survived"
            if r.returncode == 0:
                survived.append(i)
            print(f"#{i}: {verdict}", flush=True)
    finally:
        target.write_bytes(pristine)
    print(f"\n{len(ids) - len(survived)} of {len(ids)} killed; survived: {' '.join(survived)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
