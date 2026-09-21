#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Cài APK lên máy Android cắm USB, mở app, báo có crash hay không.

Vá bảng chuỗi của Hermes/Unity/dex là việc dễ làm app crash lúc mở, mà lỗi chỉ
hiện ra khi chạy thật. Script này tự động hoá vòng kiểm tra đó:

    1. lấy package name + activity chính từ APK (aapt2)
    2. gỡ bản cũ (chữ ký khác nên buộc phải gỡ — MẤT dữ liệu app)
    3. cài APK, mở app, chờ vài giây
    4. đọc `logcat -b crash` + kiểm tra process còn sống
    5. so sánh với APK gốc nếu được yêu cầu (--compare goc.apk)

Cách dùng:
    python3 devicetest.py app-vi.apk                  # cài + mở + báo kết quả
    python3 devicetest.py app-vi.apk --compare goc.apk # kiểm cả bản gốc
    python3 devicetest.py app-vi.apk --wait 20         # chờ lâu hơn
    python3 devicetest.py app-vi.apk --no-uninstall    # không gỡ bản cũ

Cảnh báo: bước gỡ làm **mất toàn bộ dữ liệu/đăng nhập** của app trên máy đó.
'''

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

WAIT_DEFAULT = 12


def _adb_path():
    for cand in (os.environ.get("ADB"),
                 shutil.which("adb"),
                 str(Path.home() / "Library/Android/sdk/platform-tools/adb")):
        if cand and Path(cand).is_file():
            return cand
    return None


def _aapt2():
    sdk = Path.home() / "Library/Android/sdk/build-tools"
    env = os.environ.get("ANDROID_BUILD_TOOLS")
    if env and (Path(env) / "aapt2").is_file():
        return str(Path(env) / "aapt2")
    if sdk.is_dir():
        for d in sorted(sdk.iterdir(), reverse=True):
            if (d / "aapt2").is_file():
                return str(d / "aapt2")
    return None


def _run(cmd, timeout=600):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def badging(apk):
    """(package, launchable_activity) đọc từ APK."""
    tool = _aapt2()
    if not tool:
        return None, None
    rc, out = _run([tool, "dump", "badging", str(apk)])
    if rc != 0:
        return None, None
    pkg = re.search(r"package: name='([^']+)'", out)
    act = re.search(r"launchable-activity: name='([^']+)'", out)
    return (pkg.group(1) if pkg else None), (act.group(1) if act else None)


def devices(adb):
    rc, out = _run([adb, "devices"])
    return [ln.split()[0] for ln in out.splitlines()[1:]
            if ln.strip() and ln.split()[-1] == "device"]


def check(apk, wait=WAIT_DEFAULT, uninstall=True, log=None):
    """Cài + mở + đọc crash. Trả về dict báo cáo."""
    if log is None:
        log = []
    adb = _adb_path()
    if not adb:
        return {"ok": False, "error": "không tìm thấy adb"}
    devs = devices(adb)
    if not devs:
        return {"ok": False, "error": "không có máy Android nào cắm USB "
                                      "(bật USB debugging)"}
    pkg, act = badging(apk)
    if not pkg:
        return {"ok": False, "error": "không đọc được package name của APK"}
    rep = {"package": pkg, "activity": act, "device": devs[0]}

    if uninstall:
        _run([adb, "uninstall", pkg])
        log.append(f"[device] đã gỡ {pkg}")
    rc, out = _run([adb, "install", "-r", str(apk)], timeout=1800)
    if "Success" not in out:
        rep.update({"ok": False, "error": "cài thất bại", "detail": out[-800:]})
        return rep
    log.append(f"[device] đã cài {Path(apk).name}")

    _run([adb, "logcat", "-c"])
    _run([adb, "logcat", "-b", "crash", "-c"])
    if act:
        _run([adb, "shell", "am", "start", "-n", f"{pkg}/{act}"])
    else:
        _run([adb, "shell", "monkey", "-p", pkg, "-c",
              "android.intent.category.LAUNCHER", "1"])
    time.sleep(wait)

    rc, pid = _run([adb, "shell", "pidof", pkg])
    alive = bool(pid.strip())
    rc, crash = _run([adb, "logcat", "-b", "crash", "-d"])
    lines = [ln for ln in crash.splitlines() if pkg in ln or "Error" in ln
             or "Exception" in ln or "FATAL" in ln]
    crashed = any(pkg in ln for ln in crash.splitlines())
    first = ""
    for ln in crash.splitlines():
        m = re.search(r"(Exception|Error):?\s*(.*)$", ln)
        if m and ("JavascriptException" in ln or "AndroidRuntime" in ln):
            first = m.group(0)[:300]
            break
    rep.update({"ok": alive and not crashed, "alive": alive,
                "crashed": crashed, "first_error": first,
                "crash_log": "\n".join(lines[:40])})
    log.append(f"[device] {pkg}: "
               + ("chạy được, không crash" if rep["ok"]
                  else ("CRASH: " + (first or "xem crash_log"))))
    return rep


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    wait = WAIT_DEFAULT
    if "--wait" in argv:
        i = argv.index("--wait")
        wait = int(argv[i + 1])
        del argv[i:i + 2]
    compare = None
    if "--compare" in argv:
        i = argv.index("--compare")
        compare = argv[i + 1]
        del argv[i:i + 2]
    uninstall = "--no-uninstall" not in argv
    argv = [a for a in argv if not a.startswith("--")]
    if not argv:
        print(__doc__)
        return 2

    log = []
    print(f"→ kiểm tra {Path(argv[0]).name}")
    rep = check(argv[0], wait, uninstall, log)
    for ln in log:
        print("  " + ln)
    if rep.get("error"):
        print("THẤT BẠI:", rep["error"])
        print(rep.get("detail", ""))
        return 2
    print(("  ✅ app mở được, không crash" if rep["ok"]
           else "  ❌ app CRASH: " + (rep.get("first_error") or "")))
    if not rep["ok"] and rep.get("crash_log"):
        print("\n--- crash log ---")
        print(rep["crash_log"][:2000])

    if compare:
        print(f"\n→ kiểm tra bản gốc {Path(compare).name} để so sánh")
        log2 = []
        rep2 = check(compare, wait, True, log2)
        for ln in log2:
            print("  " + ln)
        print(("  ✅ bản gốc cũng mở được" if rep2.get("ok")
               else "  ❌ bản gốc CŨNG crash: "
                    + (rep2.get("first_error") or "")))
        if not rep["ok"] and rep2.get("ok"):
            print("\n→ Kết luận: bản dịch làm app crash, bản gốc thì không.")
        elif not rep["ok"] and not rep2.get("ok"):
            print("\n→ Kết luận: bản gốc cũng crash — lỗi không do dịch.")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
