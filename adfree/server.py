#!/usr/bin/env python3
"""
AdFree Web — server xóa quảng cáo APK (tự host, không cần root điện thoại).

Chạy:
    python3 server.py            # mở http://localhost:8742
Cấu hình qua biến môi trường: PORT, APKTOOL, ANDROID_BUILD_TOOLS, ADFREE_KEYSTORE…
"""
import json
import os
import re
import shutil
import sys
import threading
import uuid
import zipfile
from datetime import datetime
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))  # chạy được từ mọi cwd
import assetinfo
import keyscan
import patcher
import techinfo
import api_extract
import unity_extract
# patcher (vá quảng cáo) được import lazy trong run_job — chế độ chỉ-phân-tích
# chỉ cần assetinfo + keyscan, nên server vẫn chạy được kể cả khi patcher.py
# (đang khôi phục dở từ .pyc) chưa import được.

ROOT = Path(__file__).resolve().parent
# ADFREE_DATA cho phép trỏ nơi ghi dữ liệu ra chỗ khác (volume của Docker…)
DATA_DIR = Path(os.environ.get("ADFREE_DATA", ROOT))
JOBS_DIR = DATA_DIR / "jobs"
STATIC_DIR = ROOT / "static"
DECODED_DIR = DATA_DIR / "decoded_images"
ENV_DIR = DATA_DIR / "env_report"

# MIME để xem trước file trong APK ngay trên web
MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".jfif": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
    ".bmp": "image/bmp", ".svg": "image/svg+xml", ".avif": "image/avif",
    ".mp4": "video/mp4", ".webm": "video/webm", ".mkv": "video/x-matroska",
    ".m4v": "video/mp4", ".3gp": "video/3gpp", ".mov": "video/quicktime",
    ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".oga": "audio/ogg",
    ".opus": "audio/opus", ".wav": "audio/wav", ".flac": "audio/flac",
    ".m4a": "audio/mp4", ".aac": "audio/aac", ".mid": "audio/midi",
    ".ttf": "font/ttf", ".otf": "font/otf", ".ttc": "font/collection",
    ".woff": "font/woff", ".woff2": "font/woff2",
    ".json": "application/json", ".xml": "text/xml; charset=utf-8",
    ".html": "text/html; charset=utf-8", ".txt": "text/plain; charset=utf-8",
    ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".csv": "text/csv; charset=utf-8", ".md": "text/markdown; charset=utf-8",
    ".pdf": "application/pdf", ".wasm": "application/wasm",
}
MAX_UPLOAD = int(__import__("os").environ.get("ADFREE_MAX_UPLOAD", 512 * 1024 * 1024))  # 512 MB
MAX_JOBS = 10  # giữ N job gần nhất, xóa job cũ hơn

JOBS_DIR.mkdir(exist_ok=True)

jobs = {}          # id -> dict job (thread-safe qua lock)
jobs_lock = threading.Lock()
STEPS = {
    "decode": "Giải nén APK",
    "translate": "Dịch ngôn ngữ",
    "apptech": "Nhận diện công nghệ",
    "assets": "Phân tích tài nguyên",
    "analyze": "Quét SDK quảng cáo",
    "patch": "Vô hiệu hóa quảng cáo",
    "reward": "Bật bấm-là-nhận-quà",
    "offline": "Ép SDK nghĩ offline",
    "build": "Build lại APK",
    "sign": "Ký APK",
    "done": "Hoàn tất",
}


def check_input(path):
    """
    Nhận diện đầu vào: 'apk' (APK đơn), 'bundle' (.xapk/.apks/.apkm chứa nhiều
    APK), hoặc None nếu không hợp lệ.
    """
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if "AndroidManifest.xml" in names:
                return "apk"
            if any(n.lower().endswith(".apk") for n in names):
                return "bundle"
    except (zipfile.BadZipFile, OSError):
        pass
    return None


def merge_splits(bundle_path, out_path):
    """Gộp các APK split trong .xapk/.apks thành một APK duy nhất để phân tích.

    App phát hành qua Android App Bundle bị Google Play chia nhỏ: base.apk giữ
    mã và tài nguyên chung, còn split_config.<abi>.apk giữ thư viện native,
    split_config.<dpi>/<lang> giữ ảnh và chuỗi theo máy. Phân tích riêng từng
    file thì luôn thiếu một nửa, nên gộp lại trước.
    """
    with zipfile.ZipFile(bundle_path) as bundle:
        parts = [n for n in bundle.namelist() if n.lower().endswith(".apk")]
        if not parts:
            return None, []
        # base trước để entry của nó được ưu tiên khi trùng tên
        parts.sort(key=lambda n: (0 if "base" in n.lower() else 1, n))
        seen, merged = set(), []
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as out:
            for part in parts:
                try:
                    data = bundle.read(part)
                except (KeyError, OSError):
                    continue
                try:
                    with zipfile.ZipFile(BytesIO(data)) as inner:
                        count = 0
                        for info in inner.infolist():
                            name = info.filename
                            if info.is_dir() or name.startswith("META-INF/"):
                                continue
                            if name in seen:
                                continue
                            seen.add(name)
                            out.writestr(name, inner.read(info))
                            count += 1
                except zipfile.BadZipFile:
                    continue
                merged.append(f"{part.rsplit('/', 1)[-1]} ({count} entry)")
        return out_path, merged


def run_job(job_id):
    job = jobs[job_id]
    def on_progress(step, msg, pct):
        job.update({"status": "running", "step": step,
                    "step_label": STEPS.get(step, step),
                    "progress": pct or job.get("progress", 0)})
    # Chế độ chỉ phân tích: đọc tài nguyên rồi trả báo cáo, không decode/vá/ký
    # (còn dịch ngôn ngữ thì phải decode/build/ký nên chạy nhánh patch bên dưới)
    if not job.get("block_ads") and not job.get("translate_lang"):
        try:
            target = job["input"]
            if job.get("kind") == "bundle":
                on_progress("assets", "Đang gộp các APK split…", 15)
                merged_path = str(JOBS_DIR / job_id / "merged.apk")
                result, parts = merge_splits(job["input"], merged_path)
                if result:
                    target = result
                    job["input"] = result      # các endpoint sau dùng bản gộp
                    job["log"].append("[split] đã gộp: " + ", ".join(parts))
            on_progress("assets", "Đang phân tích tài nguyên…", 30)
            report = {"assets": assetinfo.analyze(target, job["log"])}
            report["tech"] = techinfo.cached(job["input"])
            # Kiểm kê kho text: cho biết app dùng công nghệ gì và text giao
            # diện nằm ở đâu (res/values, Hermes bundle, assets…) — dịch được
            # hay không, kèm lý do.
            try:
                import apptech
                report["apptech"] = apptech.inventory(target, job["log"])
            except Exception as e:
                job["log"].append(f"[apptech] lỗi kiểm kê kho text: {e}")
            report["api"] = api_extract.cached(target)
            platforms = ", ".join(p["name"] for p in report["tech"]["platforms"])
            job["log"].append(f"[tech] nền tảng: {platforms or 'không xác định'}")
            decoded_count = assetinfo.extract_decoded_images(
                target, DECODED_DIR / job_id
            )
            if decoded_count:
                job["log"].append(f"[assets] decoded {decoded_count} XOR image(s)")
            try:
                key_count = keyscan.write_report(target, ENV_DIR / job_id)
                job["log"].append(f"[env] {key_count} API key phát hiện" if key_count
                                   else "[env] không phát hiện API key nào")
            except Exception as e:
                job["log"].append(f"[env] lỗi quét key: {e}")
            with jobs_lock:
                job.update({"status": "done", "progress": 100, "report": report,
                            "finished_at": datetime.now().isoformat(timespec="seconds")})
            prune_jobs()
        except Exception as e:
            with jobs_lock:
                job.update({"status": "error", "error": str(e), "log": job["log"],
                            "finished_at": datetime.now().isoformat(timespec="seconds")})
        return

    try:
        from patcher import Patcher, patch_bundle
    except Exception as e:  # patcher.py chưa khôi phục xong -> chỉ báo lỗi cho job vá
        with jobs_lock:
            job.update({"status": "error",
                        "error": f"Chức năng vá quảng cáo chưa sẵn sàng (patcher.py lỗi: {e}). "
                                 f"Hiện chỉ dùng được chế độ Phân tích tài nguyên.",
                        "finished_at": datetime.now().isoformat(timespec="seconds")})
        return

    patcher = Patcher(workdir=JOBS_DIR / job_id / "work",
                      fake_reward=job.get("fake_reward", True),
                      offline=job.get("offline", True),
                      analyze_assets=job.get("analyze_assets", False),
                      block_ads=job.get("block_ads", True),
                      translate_lang=job.get("translate_lang"),
                      translate_data=job.get("translate_data", False),
                      translate_code=job.get("translate_code", False))
    patcher.progress = on_progress
    try:
        if job.get("kind") == "bundle":
            # .xapk/.apks: vá base rồi ký lại cả bộ split, trả về 1 file .apks
            out = JOBS_DIR / job_id / "adfree"
            report = patch_bundle(job["input"], out, JOBS_DIR / job_id / "work",
                                  job.get("fake_reward", True), on_progress,
                                  offline=job.get("offline", True),
                                  analyze_assets=job.get("analyze_assets", False),
                                  block_ads=job.get("block_ads", True),
                                  translate_lang=job.get("translate_lang"),
                      translate_data=job.get("translate_data", False),
                      translate_code=job.get("translate_code", False))
            out_apk = Path(report["bundle"]["zip"])
        else:
            out_apk = JOBS_DIR / job_id / "patched.apk"
            report = patcher.patch(jobs[job_id]["input"], out_apk)
        if job.get("analyze_assets"):
            report["tech"] = techinfo.cached(job["input"])
            report["api"] = api_extract.cached(job["input"])
            decoded_count = assetinfo.extract_decoded_images(
                job["input"], DECODED_DIR / job_id
            )
            report.setdefault("log", report.get("log", []))
            if decoded_count:
                report["log"].append(f"[assets] decoded {decoded_count} XOR image(s)")
            try:
                key_count = keyscan.write_report(job["input"], ENV_DIR / job_id)
                report["log"].append(f"[env] {key_count} API key phát hiện" if key_count
                                      else "[env] không phát hiện API key nào")
            except Exception as e:
                report["log"].append(f"[env] lỗi quét key: {e}")
        if report.get("error"):
            # patcher trả report có 'error' (decode/build thất bại) thay vì
            # ném exception — không có cái này job vẫn báo "done" và người
            # dùng tải về một file rỗng.
            with jobs_lock:
                job.update({
                    "status": "error",
                    "error": report["error"],
                    "detail": report.get("detail", ""),
                    "report": {k: v for k, v in report.items() if k != "log"},
                    "log": report.get("log", patcher.log),
                    "finished_at": datetime.now().isoformat(timespec="seconds")})
            return
        with jobs_lock:
            job.update({"status": "done", "progress": 100,
                        "report": {k: v for k, v in report.items() if k != "log"},
                        "log": report["log"],
                        "output": str(out_apk),
                        "finished_at": datetime.now().isoformat(timespec="seconds")})
        prune_jobs()
    except Exception as e:  # lỗi bất kỳ -> trả lỗi về UI
        with jobs_lock:
            job.update({"status": "error", "error": str(e),
                        "log": patcher.log,
                        "finished_at": datetime.now().isoformat(timespec="seconds")})


ZIP_MAX_FILES = 5000
ZIP_MAX_BYTES = 512 * 1024 * 1024


def asset_bytes(job, job_id, fp):
    """Nội dung của một mục trong cây tài nguyên, kể cả các đường dẫn ảo.

    Trả về (bytes, tên file gợi ý) hoặc None nếu không đọc được.
    """
    fp = (fp or "").strip("/")
    if not fp or ".." in fp.split("/"):
        return None
    name = fp.rsplit("/", 1)[-1]
    for prefix, root in (("decoded_images/", DECODED_DIR), ("env/", ENV_DIR)):
        if fp.startswith(prefix):
            base = (root / job_id).resolve()
            target = (base / fp[len(prefix):]).resolve()
            try:
                target.relative_to(base)
            except ValueError:
                return None
            return (target.read_bytes(), name) if target.is_file() else None
    if fp.startswith("hermes-inline/"):
        parts = fp.split("/")
        marker = re.search(r"-([fm]?\d+)\.(?:json|svg)$", parts[-1])
        if len(parts) < 3 or not marker:
            return None
        if parts[1] == "lottie":
            body = assetinfo.inline_lottie_json(job["input"], marker.group(1))
        elif parts[1] == "svg":
            body = assetinfo.inline_svg_markup(job["input"], marker.group(1))
        else:
            return None
        return (body.encode("utf-8"), name) if body else None
    try:
        return assetinfo.read_file(job["input"], fp), name
    except (KeyError, zipfile.BadZipFile, OSError):
        return None


def zip_assets(job, job_id, paths):
    """Nén các mục đã chọn thành một file zip trong bộ nhớ."""
    buffer = BytesIO()
    used, missing, total = set(), 0, 0
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for fp in paths[:ZIP_MAX_FILES]:
            found = asset_bytes(job, job_id, fp)
            if not found:
                missing += 1
                continue
            data, _ = found
            total += len(data)
            if total > ZIP_MAX_BYTES:
                break
            # giữ nguyên đường dẫn trong APK: nhiều ảnh trùng tên ở các thư mục
            # mật độ khác nhau, làm phẳng thì không còn phân biệt được
            entry, index = fp.strip("/"), 2
            while entry in used:
                stem, dot, ext = fp.rpartition(".")
                entry = (f"{stem}-{index}.{ext}" if dot else f"{fp}-{index}")
                index += 1
            used.add(entry)
            archive.writestr(entry, data)
    return buffer.getvalue(), len(used), missing


def prune_jobs():
    """Xóa các job cũ quá MAX_JOBS."""
    with jobs_lock:
        ids = sorted(jobs.keys(), key=lambda i: jobs[i].get("created_at", ""))
        for old in ids[:-MAX_JOBS]:
            shutil.rmtree(JOBS_DIR / old, ignore_errors=True)
            del jobs[old]


def purge_previous_jobs(keep_ids=()):
    """Xoá sạch dữ liệu phân tích của các APK cũ khi upload APK mới.

    Job đang chạy (running) được giữ lại để không làm vỡ thread đang đọc file;
    mọi job done/error cùng thư mục jobs/, decoded_images/, env_report/ tương
    ứng (kể cả thư mục mồ côi còn sót trên đĩa sau khi server restart) đều bị
    dọn sạch. Chỉ giữ lại các id trong keep_ids.
    """
    keep = {i for i in keep_ids}
    with jobs_lock:
        for jid in list(jobs.keys()):
            if jid in keep:
                continue
            if jobs[jid].get("status") == "running":
                continue
            shutil.rmtree(JOBS_DIR / jid, ignore_errors=True)
            shutil.rmtree(DECODED_DIR / jid, ignore_errors=True)
            shutil.rmtree(ENV_DIR / jid, ignore_errors=True)
            out = jobs[jid].get("output")
            if out:
                try:
                    Path(out).unlink(missing_ok=True)
                except OSError:
                    pass
            del jobs[jid]
        # thư mục mồ côi trên đĩa (server restart làm mất danh sách memory)
        for root in (JOBS_DIR, DECODED_DIR, ENV_DIR):
            if not root.is_dir():
                continue
            for child in root.iterdir():
                if child.is_dir() and child.name not in keep:
                    shutil.rmtree(child, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "AdFree/1.0"

    # --- helpers -----------------------------------------------------------
    def send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path, mime, download_name=None):
        try:
            data = path.read_bytes()
        except OSError:
            self.send_json({"error": "không tìm thấy file"}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        if download_name:
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{download_name}"; filename*=UTF-8\'\'{download_name}',
            )
        self.end_headers()
        self.wfile.write(data)

    # --- routing -----------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
        elif path == "/api/tools":
            self.send_json(patcher.tool_status())
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/apptech", path):
            job = jobs.get(m.group(1))
            if not job:
                self.send_json({"error": "không tìm thấy job"}, 404)
                return
            import apptech
            self.send_json(apptech.inventory(job["input"], job["log"]))
        elif path == "/api/mt":
            # Trạng thái engine dịch offline: runtime/model đã tải chưa, tốn
            # bao nhiêu đĩa, ngôn ngữ nào có model. UI dùng để báo trước cho
            # người dùng là lần dịch đầu sẽ phải tải ~140 MB.
            import offline_mt
            self.send_json(offline_mt.status(check_index=True))
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/unity", path):
            job = jobs.get(m.group(1))
            if not job:
                self.send_json({"error": "không tìm thấy job"}, 404)
                return
            self.send_json({"textures": unity_extract.textures(job["input"])})
        elif path == "/api/jobs":
            with jobs_lock:
                lst = [{k: v for k, v in j.items() if k not in ("log",)}
                       for j in jobs.values()]
            self.send_json(lst)
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)", path):
            job = jobs.get(m.group(1))
            if not job:
                self.send_json({"error": "job không tồn tại"}, 404)
            else:
                self.send_json({k: v for k, v in job.items() if k != "log"})
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/log", path):
            job = jobs.get(m.group(1))
            self.send_json({"log": job.get("log", [])} if job else {"log": []})
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/download", path):
            job = jobs.get(m.group(1))
            if not job or not job.get("output"):
                self.send_json({"error": "chưa có kết quả"}, 404)
            else:
                stem = Path(job.get("filename", "app")).stem
                # Bộ split trả về .apks (cài bằng SAI / Split APKs Installer)
                ext = ".apks" if job.get("kind") == "bundle" else ".apk"
                name = stem + "-adfree" + ext
                self.send_file(Path(job["output"]), "application/vnd.android.package-archive", name)
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/package-json", path):
            job = jobs.get(m.group(1))
            if not job:
                self.send_json({"error": "không tìm thấy job"}, 404)
                return
            report = techinfo.cached(job["input"])
            if not report.get("dependencies"):
                self.send_json({"error": "app này không phải React Native"}, 404)
                return
            data = json.dumps(techinfo.package_json(report), indent=2,
                              ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="package.json"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/tree", path):
            job = jobs.get(m.group(1))
            if not job:
                self.send_json({"error": "job không tồn tại"}, 404)
            else:
                result = assetinfo.tree(job["input"])
                decoded_root = DECODED_DIR / job["id"]
                if decoded_root.is_dir():
                    for file_path in decoded_root.rglob("*"):
                        if not file_path.is_file() or file_path.name == "manifest.json":
                            continue
                        ext = file_path.suffix.lower()
                        asset_type = next((
                            gid for gid, _, _, exts in assetinfo.EXT_GROUPS if ext in exts
                        ), "other")
                        result["files"].append({
                            "p": "decoded_images/" + file_path.relative_to(decoded_root).as_posix(),
                            "s": file_path.stat().st_size,
                            "t": asset_type,
                        })
                env_root = ENV_DIR / job["id"]
                if env_root.is_dir():
                    for file_path in env_root.rglob("*"):
                        if not file_path.is_file():
                            continue
                        result["files"].append({
                            "p": "env/" + file_path.relative_to(env_root).as_posix(),
                            "s": file_path.stat().st_size,
                            "t": "env",
                        })
                self.send_json(result)
        elif m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/file", path):
            job = jobs.get(m.group(1))
            qs = parse_qs(urlparse(self.path).query)
            fp = (qs.get("path") or [""])[0].strip("/")
            if not job or not fp:
                self.send_json({"error": "thiếu path"}, 404)
                return
            if fp.startswith("decoded_images/"):
                root = (DECODED_DIR / m.group(1)).resolve()
                relative = fp[len("decoded_images/"):].strip("/")
                file_path = (root / relative).resolve()
                try:
                    file_path.relative_to(root)
                except ValueError:
                    file_path = None
                if not file_path or not file_path.is_file():
                    self.send_json({"error": "file không có trong thư mục đã giải mã"}, 404)
                    return
                self.send_file(file_path, MIME.get(file_path.suffix.lower(), "application/octet-stream"))
                return
            if fp.startswith("env/"):
                root = (ENV_DIR / m.group(1)).resolve()
                relative = fp[len("env/"):].strip("/")
                file_path = (root / relative).resolve()
                try:
                    file_path.relative_to(root)
                except ValueError:
                    file_path = None
                if not file_path or not file_path.is_file():
                    self.send_json({"error": "file không có trong báo cáo env"}, 404)
                    return
                self.send_file(file_path, MIME.get(file_path.suffix.lower(), "application/octet-stream"))
                return
            try:
                data = assetinfo.read_file(job["input"], fp)
            except (KeyError, zipfile.BadZipFile, OSError):
                self.send_json({"error": "file không có trong APK"}, 404)
                return
            ext = Path(fp).suffix.lower()
            content_type = MIME.get(ext, "application/octet-stream")
            if qs.get("preview", ["0"])[0] == "1":
                if ext == ".lottie":
                    # dotLottie là ZIP — trình phát Lottie trên web cần JSON bên
                    # trong. Tải về (không có preview=1) vẫn ra file .lottie gốc.
                    inner = assetinfo.dotlottie_animation(data)
                    if not inner:
                        self.send_json(
                            {"error": "không đọc được animation trong dotLottie"},
                            404)
                        return
                    data, content_type = inner, "application/json"
                else:
                    data = assetinfo.decode_preview(data)
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "max-age=3600")
            self.end_headers()
            self.wfile.write(data)
        elif m := re.fullmatch(r"/vendor/([A-Za-z0-9._-]+)", path):
            f = STATIC_DIR / "vendor" / m.group(1)
            if not f.is_file():
                self.send_json({"error": "không tìm thấy"}, 404)
                return
            self.send_file(f, MIME.get(f.suffix.lower(), "application/octet-stream"))
        else:
            self.send_json({"error": "không tìm thấy"}, 404)

    def do_PUT(self):
        path = urlparse(self.path).path
        if m := re.fullmatch(r"/api/jobs/([0-9a-f-]+)/zip", path):
            self.send_zip(m.group(1))
            return
        if path != "/api/jobs":
            self.send_json({"error": "sai endpoint"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_UPLOAD:
            self.send_json({"error": f"file không hợp lệ (tối đa {MAX_UPLOAD // (1024*1024)} MB)"}, 413)
            return
        job_id = str(uuid.uuid4())
        jdir = JOBS_DIR / job_id
        jdir.mkdir(parents=True)
        inp = jdir / "input.apk"
        with inp.open("wb") as f:
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
        kind = check_input(inp)
        if not kind:
            shutil.rmtree(jdir, ignore_errors=True)
            self.send_json({"error": "file không phải APK / XAPK hợp lệ"}, 400)
            return
        # Hai chế độ chính: chặn quảng cáo (vá + ký APK) và phân tích tài nguyên
        # (chỉ đọc file, không sửa/ký). Tích cả hai = vá ads + kèm báo cáo tài nguyên.
        block_ads = self.headers.get("X-Block-Ads", "1") != "0"
        analyze = self.headers.get("X-Analyze", "0") == "1"
        translate_lang = (self.headers.get("X-Translate-Lang") or
                          "").strip().lower()
        if translate_lang and not re.fullmatch(r"[a-z]{2,3}(?:-[a-z]{2,4})?",
                                               translate_lang):
            shutil.rmtree(jdir, ignore_errors=True)
            self.send_json({"error": f"mã ngôn ngữ không hợp lệ: {translate_lang}"}, 400)
            return
        if not block_ads and not analyze and not translate_lang:
            shutil.rmtree(jdir, ignore_errors=True)
            self.send_json({"error": "hãy bật ít nhất một tuỳ chọn"}, 400)
            return
        # Upload APK mới -> dọn sạch dữ liệu phân tích của các APK trước
        # (giữ lại thư mục của chính job này — nó chưa kịp đăng ký vào jobs)
        purge_previous_jobs(keep_ids={job_id})
        job = {
            "id": job_id,
            "filename": unquote(self.headers.get("X-Filename", "input.apk")),
            "input": str(inp),
            "kind": kind,
            "status": "queued",
            # X-Block-Ads: 0 để bỏ qua vá ads -> chạy chế độ chỉ-phân-tích
            "block_ads": block_ads,
            # Header X-Fake-Reward: 0 để tắt chế độ bấm-là-nhận-quà (mặc định bật khi vá)
            "fake_reward": self.headers.get("X-Fake-Reward", "1") != "0",
            # Header X-Offline: 0 để tắt chế độ ép-SDK-nghĩ-offline (mặc định bật khi vá)
            "offline": self.headers.get("X-Offline", "1") != "0",
            # Header X-Analyze: 1 để kèm phân tích tài nguyên (ảnh, video, font, lottie…)
            "analyze_assets": analyze,
            # Header X-Translate-Lang: mã ngôn ngữ (vi/en/ja…) để dịch string resources
            "translate_lang": translate_lang or None,
            # X-Translate-Data: 1 để dịch cả dữ liệu nội dung app (JSON câu
            # hỏi/bài học trong assets) — mặc định không, dễ phá nội dung
            "translate_data": self.headers.get("X-Translate-Data", "0") == "1",
            # X-Translate-Code: 1 để dịch cả chuỗi hardcode trong code (smali)
            "translate_code": self.headers.get("X-Translate-Code", "0") == "1",
            "step": None, "step_label": None, "progress": 0,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "log": [],
        }
        with jobs_lock:
            jobs[job_id] = job
        threading.Thread(target=run_job, args=(job_id,), daemon=True).start()
        self.send_json({"id": job_id, "status": "queued"})

    def send_zip(self, job_id):
        """Nén các file được tích trên UI rồi trả về một file .zip."""
        job = jobs.get(job_id)
        if not job:
            self.send_json({"error": "không tìm thấy job"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > 4 * 1024 * 1024:
            self.send_json({"error": "danh sách file không hợp lệ"}, 400)
            return
        try:
            paths = json.loads(self.rfile.read(length)).get("paths") or []
        except (ValueError, TypeError):
            self.send_json({"error": "danh sách file không hợp lệ"}, 400)
            return
        paths = [p for p in paths if isinstance(p, str)]
        if not paths:
            self.send_json({"error": "chưa chọn file nào"}, 400)
            return
        data, count, missing = zip_assets(job, job_id, paths)
        if not count:
            self.send_json({"error": "không đọc được file nào đã chọn"}, 404)
            return
        job["log"].append(
            f"[zip] đóng gói {count} file"
            + (f", bỏ qua {missing} file không đọc được" if missing else ""))
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", 'attachment; filename="assets.zip"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass  # tắt log truy cập để terminal sạch


def main():
    port = int(os.environ.get("PORT", 8742))
    # mặc định chỉ nghe máy cục bộ; đặt ADFREE_HOST=0.0.0.0 khi chạy trong
    # container hoặc sau reverse proxy — server KHÔNG có xác thực nên đừng mở
    # thẳng ra Internet
    host = os.environ.get("ADFREE_HOST", "127.0.0.1")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"AdFree Web chạy tại: http://localhost:{port}")
    print("Kéo-thả APK vào trang web → nhận APK đã xóa quảng cáo.")
    print("Lưu ý: công cụ phục vụ nghiên cứu/ứng dụng của chính bạn — không phân phối APK đã sửa của bên thứ ba.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nDừng server.")


if __name__ == "__main__":
    main()
