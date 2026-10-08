"""Run the adversarial suite and write docs/adversarial-results.{md,json}.

    python tools/run_adversarial.py           # write
    python tools/run_adversarial.py --check   # fail if the committed results are stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aauth_supervision_server.adversarial import render_markdown, run_all  # noqa: E402


def main() -> int:
    rows = run_all()
    md = render_markdown(rows)
    js = json.dumps(rows, indent=2) + "\n"
    out_md, out_js = ROOT / "docs" / "adversarial-results.md", ROOT / "docs" / "adversarial-results.json"
    if "--check" in sys.argv:
        stale = (not out_md.exists() or out_md.read_text(encoding="utf-8") != md
                 or out_js.read_text(encoding="utf-8") != js)
        print("stale: run python tools/run_adversarial.py" if stale else "results up to date")
        return 1 if stale else 0
    out_md.write_text(md, encoding="utf-8")
    out_js.write_text(js, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
