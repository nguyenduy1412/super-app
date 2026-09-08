#!/usr/bin/env python3
"""
Assetinfo — phân tích tài nguyên bên trong APK (đọc trực tiếp file zip, không cần decode).

Phân loại mọi entry trong APK theo nhóm (ảnh, SVG, video, âm thanh, font chữ,
Lottie, Rive, Spine, thư viện native…) rồi thống kê từng thư mục chứa chúng
— phục vụ tính năng "Phân tích tài nguyên" trên web.

Cách dùng CLI:
    python3 assetinfo.py input.apk
"""
import json
import sys
import zipfile
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lottie_extract  # noqa: E402  (cần sys.path ở trên)
import unity_extract  # noqa: E402

# (id, nhãn, icon, đuôi file) — các nhóm rời nhau, một file chỉ thuộc đúng 1 nhóm
EXT_GROUPS = [
    ("image", "Ảnh", "🖼️", {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp",
                             ".tif", ".tiff", ".heic", ".avif", ".jfif"}),
    ("svg", "SVG (vector)", "🖌️", {".svg"}),
    ("video", "Video", "🎬", {".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v",
                              ".3gp", ".3g2", ".ts", ".flv"}),
    ("audio", "Âm thanh", "🎵", {".mp3", ".aac", ".ogg", ".oga", ".wav", ".flac",
                                 ".m4a", ".opus", ".amr", ".mid", ".midi"}),
    ("font", "Font chữ", "🔤", {".ttf", ".otf", ".ttc", ".woff", ".woff2", ".eot"}),
    ("rive", "Rive", "🚀", {".riv"}),
    ("spine", "Spine skeleton", "🦴", {".skel", ".atlas"}),
    ("native", "Thư viện native", "⚙️", {".so"}),
]
# .json không có đuôi riêng — Lottie được nhận diện theo nội dung (xem _is_lottie)
MAX_FOLDERS = 12            # mỗi nhóm chỉ liệt kê N thư mục lớn nhất
LOTTIE_PROBE = 8192         # đọc N byte đầu của .json để nhận diện Lottie
LOTTIE_DEEP_SCAN = 4 * 1024 * 1024   # quét thêm tối đa khi phần đầu chưa đủ cờ
LOTTIE_MARKERS = (b'"fr":', b'"ip":', b'"op":')
LOTTIE_MAX_SIZE = 32 * 1024 * 1024
ZIP_MAGIC = b"PK\x03\x04"
ASSET_XOR_KEY = bytes((0xEA, 0x02, 0x0C, 0x04, 0x05, 0x02, 0xF6))
PREVIEW_IMAGE_EXTS = {".png", ".jpg", ".jpeg"}
IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
}


def _ext(name):
    """Đuôi file (chữ thường, có dấu chấm) từ đường dẫn zip dùng dấu '/'."""
    base = name.rsplit("/", 1)[-1]
    return "." + base.rsplit(".", 1)[-1].lower() if "." in base else ""


def _is_lottie(z, info):
    """Nhận diện Lottie: JSON có đủ cờ 'fr'/'ip'/'op'.

    Bộ xuất của Bodymovin đặt các cờ này ngay đầu file nên phần lớn trường hợp
    chỉ cần đọc vài KB đầu. Nhưng có bộ xuất khác (ví dụ Lottie trong Duolingo)
    đặt "layers" lên trước và "fr" tận cuối file, nên khi phần đầu trông giống
    Lottie mà chưa đủ cờ thì đọc tiếp — có giới hạn — thay vì bỏ qua.
    """
    if not 4 < info.file_size <= LOTTIE_MAX_SIZE:
        return False
    try:
        with z.open(info) as f:
            head = f.read(LOTTIE_PROBE)
            if not head.lstrip().startswith(b"{"):
                return False
            missing = {m for m in LOTTIE_MARKERS if m not in head}
            if not missing:
                return True
            # chỉ quét sâu khi phần đầu đã có dấu hiệu của Lottie
            if not any(k in head for k in (b'"layers":', b'"assets":')):
                return False
            overlap = max(len(m) for m in LOTTIE_MARKERS) - 1
            tail = head[-overlap:]
            scanned = len(head)
            while missing and scanned < LOTTIE_DEEP_SCAN:
                chunk = f.read(65536)
                if not chunk:
                    break
                scanned += len(chunk)
                window = tail + chunk
                missing -= {m for m in missing if m in window}
                tail = window[-overlap:]
            return not missing
    except (OSError, zipfile.BadZipFile):
        return False


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024


def _decode_asset_xor(data):
    """Giải ảnh assets/xN bị XOR trước khi game đưa vào BitmapFactory."""
    return bytes(byte ^ ASSET_XOR_KEY[i % len(ASSET_XOR_KEY)]
                 for i, byte in enumerate(data))


def decode_preview(data):
    """Trả về dữ liệu hiển thị được; dùng XOR khi byte đầu không phải ảnh."""
    if any(data.startswith(sig) for sig in IMAGE_SIGNATURES):
        return data
    decoded = _decode_asset_xor(data)
    if any(decoded.startswith(sig) for sig in IMAGE_SIGNATURES):
        return decoded
    return data


def extract_decoded_images(apk_path, output_dir):
    """Xuất ảnh assets/xN bị XOR, giữ cấu trúc thư mục trong APK."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    extracted = 0
    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist():
            if info.is_dir() or _ext(info.filename) not in PREVIEW_IMAGE_EXTS:
                continue
            data = archive.read(info)
            if any(data.startswith(signature) for signature in IMAGE_SIGNATURES):
                continue
            decoded = _decode_asset_xor(data)
            if not any(decoded.startswith(signature) for signature in IMAGE_SIGNATURES):
                continue
            destination = out / info.filename.lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(decoded)
            extracted += 1
    return extracted


def classify(z, info):
    """Loại tài nguyên của một entry zip (id nhóm, hoặc 'other')."""
    ext = _ext(info.filename)
    for gid, _, _, exts in EXT_GROUPS:
        if ext in exts:
            return gid
    if ext == ".lottie":
        # dotLottie là file ZIP chứa manifest.json + animations/*.json, hoàn toàn
        # khác Rive — xếp chung nhóm thì UI đưa nhầm cho trình phát Rive.
        try:
            with z.open(info) as f:
                head = f.read(4)
        except (OSError, zipfile.BadZipFile):
            return "other"
        return "dotlottie" if head == ZIP_MAGIC else "lottie"
    if ext == ".json" and _is_lottie(z, info):
        return "lottie"
    return "other"


def dotlottie_animation(data):
    """JSON animation bên trong một file dotLottie; b"" nếu không đọc được.

    manifest.json liệt kê id animation, file nằm ở animations/<id>.json. Có bản
    không kèm manifest nên vẫn lùi về lấy file .json đầu tiên trong animations/.
    """
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            names = archive.namelist()
            wanted = []
            if "manifest.json" in names:
                try:
                    manifest = json.loads(archive.read("manifest.json"))
                    wanted = [f"animations/{a['id']}.json"
                              for a in manifest.get("animations", [])
                              if isinstance(a, dict) and a.get("id")]
                except (ValueError, TypeError, KeyError):
                    wanted = []
            wanted += sorted(n for n in names
                             if n.startswith("animations/")
                             and n.endswith(".json"))
            for name in wanted:
                if name in names:
                    return archive.read(name)
    except (OSError, zipfile.BadZipFile, KeyError):
        pass
    return b""


def tree(apk_path):
    """Toàn bộ file trong APK dạng phẳng: đường dẫn + kích thước + loại.

    UI web dùng danh sách này dựng cây thư mục kiểu VSCode và lọc theo nhóm.
    """
    out = []
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            out.append({"p": info.filename.lstrip("/"), "s": info.file_size,
                        "t": classify(z, info)})
    for item in unity_extract.textures(apk_path):
        out.append({"p": _unity_path(item), "s": item["bytes"],
                    "t": "unity-texture"})
    return {"files": out}


def _unity_path(item):
    """Đường dẫn ảo của một Texture2D lấy từ container Unity."""
    name = item.get("name", "tex")
    return (f"unity-textures/{item.get('container', 'bundle')}"
            f"/{name}-u{item['index']}.png")


def read_file(apk_path, path):
    """Đọc nội dung một file trong APK theo đúng tên entry zip."""
    with zipfile.ZipFile(apk_path) as z:
        return z.read((path or "").strip("/"))


def analyze(apk_path, log=None):
    """Quét APK, trả về báo cáo phân loại tài nguyên theo nhóm + thư mục."""
    out_files = tree(apk_path)["files"]
    groups = {}  # id -> {"files": n, "size": b, "folders": {dir: [n, b]}}
    total_files = total_size = 0
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            total_files += 1
            total_size += info.file_size
            gid = classify(z, info)
            if gid == "other":
                continue
            g = groups.setdefault(gid, {"files": 0, "size": 0, "folders": {}})
            g["files"] += 1
            g["size"] += info.file_size
            d = info.filename.rsplit("/", 1)[0]
            f = g["folders"].setdefault(d, [0, 0])
            f[0] += 1
            f[1] += info.file_size

    meta = {gid: (label, icon) for gid, label, icon, _ in EXT_GROUPS}
    meta["lottie"] = ("Lottie animation", "✨")
    meta["dotlottie"] = ("dotLottie (.lottie)", "🎞️")
    cats = []
    for gid in [g for g, *_ in EXT_GROUPS] + ["lottie", "dotlottie"]:
        if gid not in groups:
            continue
        g = groups[gid]
        folders = sorted(g["folders"].items(), key=lambda kv: -kv[1][1])
        shown = folders[:MAX_FOLDERS]
        label, icon = meta[gid]
        cats.append({
            "id": gid, "label": label, "icon": icon,
            "files": g["files"], "size": g["size"],
            "folders": [{"path": d or "/", "files": n, "size": b}
                        for d, (n, b) in shown],
            "folders_more": len(folders) - len(shown),
        })

    n_unity = sum(1 for f in out_files if f["t"] == "unity-texture")
    if n_unity:
        cats.append({
            "id": "unity-texture", "label": "Texture Unity", "icon": "🎮",
            "files": n_unity, "size": 0, "folders": [], "folders_more": 0,
        })
    report = {"total_files": total_files, "total_size": total_size,
              "categories": cats}
    if log is not None:
        summary = ", ".join(f"{c['icon']} {c['label']}: {c['files']}"
                            for c in cats) or "không có tài nguyên nào nổi bật"
        log.append(f"[assets] {total_files} file ({_human(total_size)}): {summary}")
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    print(json.dumps(analyze(Path(sys.argv[1])), indent=2, ensure_ascii=False))
