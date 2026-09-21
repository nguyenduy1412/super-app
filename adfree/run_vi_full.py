#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dịch full english_grammar_test sang tiếng Việt (UI + JSON nội dung)."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from patcher import Patcher  # noqa: E402

INP = Path("/Volumes/Razer/code/superapp/english_grammar_test_signed.apk")
OUT = Path("/Volumes/Razer/code/superapp/english_grammar_test-vi-full.apk")
WORK = ROOT / "jobs" / "vi-full-run"


def prog(step, label, pct):
    print(f"[{pct:3d}%] {step}: {label}", flush=True)


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    p = Patcher(
        workdir=WORK / "work",
        fake_reward=False,
        offline=False,
        analyze_assets=False,
        block_ads=False,
        translate_lang="vi",
        deep_translate=True,
        translate_data=True,
        translate_code=False,
    )
    p.progress = prog
    t0 = time.time()
    report = p.patch(INP, OUT)
    elapsed = int(time.time() - t0)
    print("=== DONE ===", flush=True)
    print("ok", report.get("ok"), "error", report.get("error"), flush=True)
    print("elapsed_sec", elapsed, flush=True)
    print(
        "output", OUT, "exists", OUT.is_file(),
        "size", OUT.stat().st_size if OUT.is_file() else 0,
        flush=True,
    )
    tr = report.get("translate") or {}
    print("res_translate", tr.get("translated"), "/", tr.get("strings"), flush=True)
    ft = report.get("flutter_translate") or {}
    print("flutter", ft.get("translated"), "embedded", ft.get("embedded"), flush=True)
    dt = report.get("deep_translate") or {}
    print("deep_translated", dt.get("translated"), "files", dt.get("files_changed"), flush=True)
    for s in (dt.get("stores") or []):
        print(" ", s.get("kind"), s.get("translated"), "/", s.get("candidates"), flush=True)
    slim = {k: report[k] for k in report if k != "log"}
    (WORK / "report.json").write_text(
        json.dumps(slim, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (WORK / "log.txt").write_text("\n".join(report.get("log") or []), encoding="utf-8")
    if not report.get("ok"):
        print("DETAIL", (report.get("detail") or "")[-2000:], flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
