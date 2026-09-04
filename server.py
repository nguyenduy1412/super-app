"""HTTP controller: serve static UI and expose JSON API."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict
from urllib.parse import parse_qs, urlparse

try:
    from services import (
        DEFAULT_VOLUME,
        HOST,
        JOBS,
        JOBS_LOCK,
        MANAGED_DIR_NAME,
        PORT,
        SCAN_DETAILS,
        SCAN_CURRENT_ITEM,
        SCAN_LOCK,
        SCAN_PROGRESS,
        SCAN_STATUS,
        SCAN_SUMMARY,
        JobLog,
        app_json,
        build_data_plan,
        build_plan,
        clean_selected_paths,
        delete_app_files,
        delete_unavailable_simulators,
        find_app,
        get_cleaner_status,
        human_size,
        preview_data_json,
        preview_json,
        process_plan,
        delete_stuck_update,
        recover_stuck_update,
        scan_app_related_files,
        scan_apps,
        scan_stuck_updates,
        scan_volumes,
        start_background_cleaner_scan,
        start_background_scan,
    )
except ImportError:
    from .services import (
        DEFAULT_VOLUME,
        HOST,
        JOBS,
        JOBS_LOCK,
        MANAGED_DIR_NAME,
        PORT,
        SCAN_DETAILS,
        SCAN_CURRENT_ITEM,
        SCAN_LOCK,
        SCAN_PROGRESS,
        SCAN_STATUS,
        SCAN_SUMMARY,
        JobLog,
        app_json,
        build_data_plan,
        build_plan,
        clean_selected_paths,
        delete_app_files,
        delete_unavailable_simulators,
        find_app,
        get_cleaner_status,
        human_size,
        preview_data_json,
        preview_json,
        process_plan,
        delete_stuck_update,
        recover_stuck_update,
        scan_app_related_files,
        scan_apps,
        scan_stuck_updates,
        scan_volumes,
        start_background_cleaner_scan,
        start_background_scan,
    )

WEB_DIR = Path(__file__).resolve().parent / "web"
INDEX_HTML = (WEB_DIR / "index.html").read_text(encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return

    def send_json(self, payload: Dict[str, object], status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_body(self) -> Dict[str, object]:
        size = int(self.headers.get("Content-Length", "0") or "0")
        return json.loads(self.rfile.read(size).decode("utf-8") if size else "{}")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                data = INDEX_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif parsed.path == "/api/apps":
                qs = parse_qs(parsed.query)
                volume = Path(qs.get("volume", [str(DEFAULT_VOLUME)])[0])
                self.send_json({"apps": [app_json(app, volume) for app in scan_apps(volume)]})
            elif parsed.path == "/api/volumes":
                self.send_json({"volumes": [str(v) for v in scan_volumes()]})
            elif parsed.path == "/api/preview":
                qs = parse_qs(parsed.query)
                volume = Path(qs.get("volume", [str(DEFAULT_VOLUME)])[0])
                self.send_json(
                    preview_json(
                        build_plan(
                            find_app(qs["app_path"][0], volume),
                            volume,
                        )
                    )
                )
            elif parsed.path == "/api/preview-data":
                qs = parse_qs(parsed.query)
                volume = Path(qs.get("volume", [str(DEFAULT_VOLUME)])[0])
                app = find_app(qs["app_path"][0], volume)
                self.send_json(preview_data_json(app, volume))
            elif parsed.path == "/api/job":
                qs = parse_qs(parsed.query)
                with JOBS_LOCK:
                    job = JOBS.get(qs.get("id", [""])[0])
                    if not job:
                        raise RuntimeError("Khong thay job.")
                    self.send_json(dict(job))
            elif parsed.path == "/api/storage/status":
                with SCAN_LOCK:
                    self.send_json(
                        {
                            "status": SCAN_STATUS,
                            "progress": SCAN_PROGRESS,
                            "current_item": SCAN_CURRENT_ITEM,
                            "summary": SCAN_SUMMARY,
                        }
                    )
            elif parsed.path == "/api/storage/details":
                qs = parse_qs(parsed.query)
                category = qs.get("category", [""])[0]
                self.send_json({"items": SCAN_DETAILS.get(category, [])})
            elif parsed.path == "/api/app-files":
                qs = parse_qs(parsed.query)
                app_path = qs.get("app_path", [""])[0]
                volume = Path(qs.get("volume", [str(DEFAULT_VOLUME)])[0])
                app = find_app(app_path, volume)
                files = scan_app_related_files(app)
                total = sum(f["size"] for f in files)
                self.send_json(
                    {
                        "app": app_json(app, volume),
                        "files": files,
                        "total_size": total,
                        "total_size_human": human_size(total),
                    }
                )
            elif parsed.path == "/api/stuck-updates":
                qs = parse_qs(parsed.query)
                volume = Path(qs.get("volume", [str(DEFAULT_VOLUME)])[0])
                self.send_json(scan_stuck_updates(volume))
            elif parsed.path == "/api/cleaner/status":
                self.send_json(get_cleaner_status())
            else:
                self.send_json({"error": "Not found"}, 404)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = self.read_body()
            if parsed.path == "/api/move":
                volume = Path(str(body.get("volume") or DEFAULT_VOLUME))
                plan = build_plan(
                    find_app(str(body["app_path"]), volume),
                    volume,
                )
                job_id = uuid.uuid4().hex
                with JOBS_LOCK:
                    JOBS[job_id] = {
                        "id": job_id,
                        "status": "running",
                        "status_text": "Dang chuan bi...",
                        "logs": [],
                    }

                def run() -> None:
                    log = JobLog(job_id)
                    try:
                        process_plan(plan, log)
                    except Exception as exc:
                        log.error(str(exc))

                threading.Thread(target=run, daemon=True).start()
                self.send_json({"job_id": job_id})
            elif parsed.path == "/api/move-data":
                volume = Path(str(body.get("volume") or DEFAULT_VOLUME))
                app = find_app(str(body["app_path"]), volume)
                plan = build_data_plan(app, volume)
                job_id = uuid.uuid4().hex
                with JOBS_LOCK:
                    JOBS[job_id] = {
                        "id": job_id,
                        "status": "running",
                        "status_text": "Dang chuan bi chuyen du lieu...",
                        "logs": [],
                    }

                def run_data() -> None:
                    log = JobLog(job_id)
                    try:
                        process_plan(plan, log)
                    except Exception as exc:
                        log.error(str(exc))

                threading.Thread(target=run_data, daemon=True).start()
                self.send_json({"job_id": job_id})
            elif parsed.path == "/api/open-folder":
                target = Path(str(body.get("volume") or DEFAULT_VOLUME)) / MANAGED_DIR_NAME
                target.mkdir(parents=True, exist_ok=True)
                subprocess.run(["open", str(target)], check=False)
                self.send_json({"ok": True})
            elif parsed.path == "/api/storage/scan":
                start_background_scan()
                self.send_json({"ok": True})
            elif parsed.path == "/api/app-delete":
                paths = list(body.get("paths", []))
                if not paths:
                    raise RuntimeError("Không có đường dẫn nào được chọn.")
                results = delete_app_files([str(p) for p in paths])
                self.send_json({"results": results})
            elif parsed.path == "/api/recover-stuck-update":
                volume = Path(str(body.get("volume") or DEFAULT_VOLUME))
                temp_dir = str(body.get("temp_dir") or "")
                if not temp_dir:
                    raise RuntimeError("Thieu duong dan thu muc ShipIt bi ket.")
                job_id = uuid.uuid4().hex
                with JOBS_LOCK:
                    JOBS[job_id] = {
                        "id": job_id,
                        "status": "running",
                        "status_text": "Dang khoi phuc ban cap nhat...",
                        "logs": [],
                    }

                def run_recover() -> None:
                    log = JobLog(job_id)
                    try:
                        recover_stuck_update(volume, temp_dir, log)
                    except Exception as exc:
                        log.error(str(exc))

                threading.Thread(target=run_recover, daemon=True).start()
                self.send_json({"job_id": job_id})
            elif parsed.path == "/api/delete-stuck-update":
                temp_dir = str(body.get("temp_dir") or "")
                if not temp_dir:
                    raise RuntimeError("Thieu duong dan thu muc bi ket.")
                job_id = uuid.uuid4().hex
                with JOBS_LOCK:
                    JOBS[job_id] = {
                        "id": job_id,
                        "status": "running",
                        "status_text": "Dang xoa ban cap nhat...",
                        "logs": [],
                    }

                def run_delete() -> None:
                    log = JobLog(job_id)
                    try:
                        delete_stuck_update(temp_dir, log)
                    except Exception as exc:
                        log.error(str(exc))

                threading.Thread(target=run_delete, daemon=True).start()
                self.send_json({"job_id": job_id})
            elif parsed.path == "/api/cleaner/scan":
                start_background_cleaner_scan()
                self.send_json({"ok": True})
            elif parsed.path == "/api/cleaner/clean":
                paths = list(body.get("paths", []))
                if not paths:
                    raise RuntimeError("Chua chon muc nao de xoa.")
                job_id = uuid.uuid4().hex
                with JOBS_LOCK:
                    JOBS[job_id] = {
                        "id": job_id,
                        "status": "running",
                        "status_text": "Dang xoa cache...",
                        "logs": [],
                    }

                def run_clean() -> None:
                    log = JobLog(job_id)
                    try:
                        clean_selected_paths([str(p) for p in paths], log)
                    except Exception as exc:
                        log.error(str(exc))

                threading.Thread(target=run_clean, daemon=True).start()
                self.send_json({"job_id": job_id})
            elif parsed.path == "/api/cleaner/delete-unavailable-simulators":
                job_id = uuid.uuid4().hex
                with JOBS_LOCK:
                    JOBS[job_id] = {
                        "id": job_id,
                        "status": "running",
                        "status_text": "Dang xoa simulator khong dung duoc...",
                        "logs": [],
                    }

                def run_delete_sims() -> None:
                    log = JobLog(job_id)
                    try:
                        delete_unavailable_simulators(log)
                    except Exception as exc:
                        log.error(str(exc))

                threading.Thread(target=run_delete_sims, daemon=True).start()
                self.send_json({"job_id": job_id})
            else:
                self.send_json({"error": "Not found"}, 404)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((HOST, PORT))
            return PORT
        except OSError:
            sock.bind((HOST, 0))
            return int(sock.getsockname()[1])


def main() -> int:
    if sys.platform != "darwin":
        print("Tool nay danh cho macOS.", file=sys.stderr)
        return 1
    if not (WEB_DIR / "index.html").is_file():
        print(f"Khong tim thay giao dien: {WEB_DIR / 'index.html'}", file=sys.stderr)
        return 1
    port = free_port()
    server = ThreadingHTTPServer((HOST, port), Handler)
    url = f"http://{HOST}:{port}/"
    print(f"Mac App Mover web UI: {url}")
    print("Nhan Ctrl+C de tat.")
    start_background_scan()
    threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
