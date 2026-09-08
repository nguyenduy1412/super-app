"""HTTP controller: serve Super App (Mac App Mover & GitKraken Web) and expose JSON APIs."""

from __future__ import annotations

import json
import mimetypes
import os
import socket
import subprocess
import sys
import threading
import time
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

try:
    from git_services import (
        scan_recent_repos,
        get_repo_data,
        get_commit_details,
        get_file_diff,
        execute_action,
    )
except ImportError:
    from .git_services import (
        scan_recent_repos,
        get_repo_data,
        get_commit_details,
        get_file_diff,
        execute_action,
    )

WEB_DIR = Path(__file__).resolve().parent / "web"

# SSE watcher registry for GitKraken: {repo_path: [queue, ...]}
_sse_lock = threading.Lock()
_sse_clients: Dict[str, list] = {}


def _run_git_status(repo_path: str) -> str:
    """Run git status --porcelain quickly for SSE watcher."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            cwd=repo_path,
            capture_output=True, text=True, timeout=3
        )
        return result.stdout
    except Exception:
        return ""


def _sse_watcher_thread(repo_path: str) -> None:
    """Background thread: polls git status every 200ms, pushes SSE event when changed."""
    last_status = None
    while True:
        with _sse_lock:
            clients = _sse_clients.get(repo_path, [])
        if not clients:
            with _sse_lock:
                _sse_clients.pop(repo_path, None)
            break
        current = _run_git_status(repo_path)
        if current != last_status:
            last_status = current
            msg = "data: changed\n\n"
            dead = []
            with _sse_lock:
                clients = list(_sse_clients.get(repo_path, []))
            for q in clients:
                try:
                    q.append(msg)
                except Exception:
                    dead.append(q)
            if dead:
                with _sse_lock:
                    existing = _sse_clients.get(repo_path, [])
                    _sse_clients[repo_path] = [q for q in existing if q not in dead]
        time.sleep(0.2)



class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, TimeoutError):
            pass

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def send_json(self, payload: Dict[str, object], status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(data)

    def read_body(self) -> Dict[str, object]:
        size = int(self.headers.get("Content-Length", "0") or "0")
        return json.loads(self.rfile.read(size).decode("utf-8") if size else "{}")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                index_path = WEB_DIR / "index.html"
                data = index_path.read_text(encoding="utf-8").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif parsed.path == "/app-mover":
                mover_path = WEB_DIR / "mover.html"
                data = mover_path.read_text(encoding="utf-8").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif parsed.path == "/gitkraken":
                gk_path = WEB_DIR / "gitkraken.html"
                data = gk_path.read_text(encoding="utf-8").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif parsed.path == "/adfree":
                # AdFree chạy server riêng (mặc định cổng 8742) — chuyển hướng
                # iframe sang đó. Đổi địa chỉ qua biến môi trường ADFREE_URL.
                adfree_url = os.environ.get("ADFREE_URL", "http://localhost:8742/")
                self.send_response(302)
                self.send_header("Location", adfree_url)
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
            elif parsed.path == "/netfence":
                # NetFence chạy server riêng (mặc định cổng 8748) — chuyển hướng
                # iframe sang đó. Đổi địa chỉ qua biến môi trường NETFENCE_URL.
                netfence_url = os.environ.get("NETFENCE_URL", "http://localhost:8748/")
                self.send_response(302)
                self.send_header("Location", netfence_url)
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
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
            # === GitKraken APIs ===
            elif parsed.path == "/api/repos":
                repos = scan_recent_repos()
                self.send_json({"ok": True, "repos": repos})
            elif parsed.path == "/api/git":
                qs = parse_qs(parsed.query)
                repo_path = (qs.get("path", [""])[0] or os.getcwd()).strip()
                target_sha = qs.get("sha", [None])[0]
                if target_sha and target_sha.lower() != "wip":
                    target_file = qs.get("file", [None])[0]
                    all_files = qs.get("allFiles", ["false"])[0] == "true"
                    data = get_commit_details(repo_path, target_sha, target_file, all_files)
                    self.send_json(data)
                    return
                limit = int(qs.get("limit", ["1000"])[0])
                status_only = qs.get("statusOnly", ["0"])[0] == "1"
                data = get_repo_data(repo_path, limit, status_only=status_only)
                self.send_json(data)
            elif parsed.path == "/api/git/commit":
                qs = parse_qs(parsed.query)
                repo_path = (qs.get("path", [""])[0] or os.getcwd()).strip()
                sha = qs.get("sha", [""])[0]
                target_file = qs.get("file", [None])[0]
                all_files = qs.get("allFiles", ["false"])[0] == "true"
                if not sha:
                    self.send_json({"error": "Missing sha parameter"}, status=400)
                    return
                data = get_commit_details(repo_path, sha, target_file, all_files)
                self.send_json(data)
            elif parsed.path == "/api/git/diff":
                qs = parse_qs(parsed.query)
                repo_path = (qs.get("path", [""])[0] or os.getcwd()).strip()
                file_path = qs.get("file", [""])[0]
                sha = qs.get("sha", [None])[0]
                staged = qs.get("staged", ["false"])[0] == "true"
                if not file_path:
                    self.send_json({"error": "Missing file parameter"}, status=400)
                    return
                diff_text = get_file_diff(repo_path, file_path, sha, staged)
                self.send_json({"ok": True, "diff": diff_text})
            elif parsed.path == "/api/git/watch":
                qs = parse_qs(parsed.query)
                repo_path = (qs.get("path", [""])[0] or os.getcwd()).strip()
                try:
                    git_root = subprocess.run(
                        ["git", "rev-parse", "--show-toplevel"],
                        cwd=repo_path, capture_output=True, text=True, timeout=3
                    ).stdout.strip() or repo_path
                except Exception:
                    git_root = repo_path

                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()

                my_queue: list = []
                with _sse_lock:
                    if git_root not in _sse_clients:
                        _sse_clients[git_root] = []
                        t = threading.Thread(
                            target=_sse_watcher_thread,
                            args=(git_root,), daemon=True
                        )
                        t.start()
                    _sse_clients[git_root].append(my_queue)

                try:
                    self.wfile.write(b"data: connected\n\n")
                    self.wfile.flush()
                except Exception:
                    pass

                try:
                    while True:
                        if my_queue:
                            msg = my_queue.pop(0)
                            self.wfile.write(msg.encode("utf-8"))
                            self.wfile.flush()
                        else:
                            time.sleep(0.1)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    with _sse_lock:
                        clients = _sse_clients.get(git_root, [])
                        if my_queue in clients:
                            clients.remove(my_queue)
                return
            # === Static Assets (GitKraken & shared) ===
            elif (
                parsed.path.startswith(("/assets/", "/fonts/", "/images/", "/svg-icons/", "/templates/"))
                or parsed.path in ("/favicon.ico", "/robots.txt")
            ):
                rel_path = parsed.path.lstrip("/")
                file_path = (WEB_DIR / rel_path).resolve()
                if str(file_path).startswith(str(WEB_DIR)) and file_path.is_file():
                    mime, _ = mimetypes.guess_type(str(file_path))
                    mime = mime or "application/octet-stream"
                    content = file_path.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", f"{mime}; charset=utf-8" if "text" in mime or "json" in mime or "javascript" in mime else mime)
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("Cache-Control", "public, max-age=86400")
                    self.end_headers()
                    self.wfile.write(content)
                    return
                self.send_json({"error": "File not found"}, 404)
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
            elif parsed.path == "/api/git/action":
                action = str(body.get("action") or "")
                repo_path = str(body.get("repoPath") or os.getcwd())
                if not action:
                    self.send_json({"error": "Missing action parameter"}, status=400)
                    return
                params = body.get("params", body)
                result = execute_action(repo_path, action, params)
                self.send_json(result)
            else:
                self.send_json({"error": "Not found"}, 404)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 500)


def free_port() -> int:
    """Kiểm tra cổng mặc định. Không tự fallback cổng random để tránh trùng instance."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((HOST, PORT))
            return PORT
        except OSError:
            return 0


class SuperAppServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        """Bỏ qua các lỗi ngắt kết nối thông thường của client trình duyệt."""
        exc_type, exc_value, _ = sys.exc_info()
        if exc_type in (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, TimeoutError):
            return
        super().handle_error(request, client_address)


def main() -> int:
    if sys.platform != "darwin":
        print("Tool nay danh cho macOS.", file=sys.stderr)
        return 1
    if not (WEB_DIR / "index.html").is_file():
        print(f"Khong tim thay giao dien: {WEB_DIR / 'index.html'}", file=sys.stderr)
        return 1
    port = free_port()
    if port == 0:
        # Đã có Super App server chạy trước đó: không nhân bản thêm instance,
        # chỉ mở lại đúng URL đang sống để lần bấm sau cũng dùng được.
        url = f"http://{HOST}:{PORT}/"
        print(f"✓ Super App server da chay san tai: {url}")
        webbrowser.open(url)
        return 0
    server = SuperAppServer((HOST, port), Handler)
    url = f"http://{HOST}:{port}/"
    print("=" * 60)
    print(f"⚡ SUPER APP SUITE (Mac App Mover & GitKraken Web)")
    print(f"🌐 Web UI: {url}")
    print(f"📦 Drawer chuyển đổi ứng dụng đặt ở góc trên màn hình.")
    print("=" * 60)
    start_background_scan()
    threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
