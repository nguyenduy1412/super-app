from __future__ import annotations

import datetime as dt
import fnmatch
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


HOME = Path.home()
USER_LIBRARY = HOME / "Library"
DEFAULT_VOLUME = Path("/Volumes/Razer")
MANAGED_DIR_NAME = "MacAppMover"
HOST = "127.0.0.1"
PORT = 8765
SKIP_COPY_NAMES = {".com.apple.containermanagerd.metadata.plist"}

JOBS: Dict[str, Dict[str, object]] = {}
JOBS_LOCK = threading.Lock()


@dataclass(frozen=True)
class AppEntry:
    name: str
    path: Path
    bundle_id: str
    display_name: str
    executable_name: str
    already_linked: bool


@dataclass(frozen=True)
class MoveItem:
    source: Path
    target: Path
    original_archive: Path
    label: str


@dataclass(frozen=True)
class MovePlan:
    app: AppEntry
    managed_root: Path
    timestamp: str
    items: List[MoveItem]


class CommandFailure(RuntimeError):
    def __init__(self, args: Sequence[str], returncode: int, output: str) -> None:
        self.output = output.strip()
        msg = f"{list(args)!r} failed with exit code {returncode}"
        if self.output:
            msg += f": {self.output}"
        super().__init__(msg)


def should_skip(path: Path) -> bool:
    if path.name in SKIP_COPY_NAMES:
        return True
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    if stat.S_ISLNK(mode):
        return False
    return (
        stat.S_ISSOCK(mode)
        or stat.S_ISFIFO(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISCHR(mode)
    )


def human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{num_bytes} B"


def safe_size(path: Path) -> int:
    try:
        if should_skip(path):
            return 0
        if path.is_symlink():
            return path.lstat().st_size
        if path.is_file():
            st = path.stat()
            alloc = st.st_blocks * 512
            return alloc if (alloc > 0 or st.st_size == 0) else st.st_size
        total = 0
        for root, dirs, files in os.walk(path, topdown=True):
            root_path = Path(root)
            kept = []
            for name in dirs:
                item = root_path / name
                if item.is_symlink():
                    total += item.lstat().st_size
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in files:
                item = root_path / name
                if not should_skip(item):
                    if item.is_symlink():
                        total += item.lstat().st_size
                    else:
                        st = item.stat()
                        alloc = st.st_blocks * 512
                        total += alloc if (alloc > 0 or st.st_size == 0) else st.st_size
        return total
    except OSError:
        return 0


def safe_logical_size(path: Path) -> int:
    try:
        if should_skip(path):
            return 0
        if path.is_symlink():
            return path.lstat().st_size
        if path.is_file():
            return path.stat().st_size
        total = 0
        for root, dirs, files in os.walk(path, topdown=True):
            root_path = Path(root)
            kept = []
            for name in dirs:
                item = root_path / name
                if item.is_symlink():
                    total += item.lstat().st_size
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in files:
                item = root_path / name
                if should_skip(item):
                    continue
                if item.is_symlink():
                    total += item.lstat().st_size
                else:
                    total += item.stat().st_size
        return total
    except OSError:
        return 0


def du_size(path: Path) -> int:
    """Tính dung lượng dùng `du -sk` — resolve symlinks, cùng chuẩn với macOS Settings.

    macOS Settings dùng cùng cơ chế: đếm dung lượng thực tế kể cả khi path là symlink.
    rc=1 là bình thường trên macOS khi có subfolder bị từ chối quyền truy cập — `du`
    vẫn trả về tổng hợp lệ trong trường hợp đó, nên ta vẫn parse output.
    Fallback về safe_size() nếu không parse được.
    """
    try:
        result = subprocess.run(
            ["du", "-sk", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=120,
        )
        # rc=0: thành công hoàn toàn; rc=1: có lỗi permission nhưng vẫn có kết quả
        if result.returncode in (0, 1) and result.stdout.strip():
            parts = result.stdout.strip().split("\t", 1)
            if parts and parts[0].isdigit():
                return int(parts[0]) * 1024  # du trả về KB → bytes
    except Exception:
        pass
    return safe_size(path)  # fallback


def get_apfs_disk_info() -> Tuple[int, int, int]:
    """Lấy dung lượng đĩa đúng từ APFS container — cùng chuẩn với macOS Settings.

    macOS Settings hiển thị dung lượng của APFS container (tổng tất cả volumes),
    không phải chỉ volume `/`. Hàm này dùng `diskutil info disk3s5` (Data volume)
    để lấy `Volume Used Space` và `Container Total/Free Space`.

    Returns: (total_bytes, used_bytes, free_bytes)
    """
    try:
        # Lấy thông tin disk device của /
        stat_result = subprocess.run(
            ["df", "-P", "/"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        device = ""
        for line in stat_result.stdout.splitlines()[1:]:
            parts = line.split()
            if parts:
                device = parts[0]  # e.g. /dev/disk3s1s1
                break

        # Tách tên disk gốc: disk3s1s1 → disk3
        m = re.match(r"(/dev/)?(disk\d+)", device)
        if not m:
            raise ValueError(f"Cannot parse device: {device}")
        base_disk = m.group(2)  # e.g. disk3

        # Tìm Data volume (thường là diskXs5 hoặc có chữ "Data" trong tên)
        list_result = subprocess.run(
            ["diskutil", "list", base_disk],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        data_disk = ""
        for line in list_result.stdout.splitlines():
            if "Data" in line or "data" in line:
                # Lấy identifier cuối dòng, e.g. disk3s5
                parts = line.split()
                if parts:
                    data_disk = parts[-1]
                    break

        if not data_disk:
            # Fallback: thử volume chính (diskXs5)
            data_disk = f"{base_disk}s5"

        # Lấy thông tin volume Data
        info_result = subprocess.run(
            ["diskutil", "info", data_disk],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10
        )
        total_bytes = used_bytes = free_bytes = 0
        for line in info_result.stdout.splitlines():
            line = line.strip()
            if "Volume Used Space:" in line:
                m2 = re.search(r"\((\d+)\s+Bytes\)", line)
                if m2:
                    used_bytes = int(m2.group(1))
            elif "Container Total Space:" in line:
                m2 = re.search(r"\((\d+)\s+Bytes\)", line)
                if m2:
                    total_bytes = int(m2.group(1))
            elif "Container Free Space:" in line:
                m2 = re.search(r"\((\d+)\s+Bytes\)", line)
                if m2:
                    free_bytes = int(m2.group(1))

        if total_bytes > 0 and used_bytes > 0:
            return total_bytes, used_bytes, free_bytes
    except Exception:
        pass

    # Fallback về shutil nếu diskutil thất bại
    return shutil.disk_usage("/")



def safe_count(path: Path) -> int:
    try:
        if should_skip(path):
            return 0
        if path.is_file() or path.is_symlink():
            return 1
        count = 0
        for root, dirs, files in os.walk(path, topdown=True):
            root_path = Path(root)
            kept = []
            for name in dirs:
                item = root_path / name
                if item.is_symlink():
                    count += 1
                else:
                    kept.append(name)
            dirs[:] = kept
            count += sum(1 for name in files if not should_skip(root_path / name))
        return count
    except OSError:
        return 0


def same_data(source: Path, target: Path) -> bool:
    if not target.exists() and not target.is_symlink():
        return False
    if source.is_file():
        return target.is_file() and source.stat().st_size == target.stat().st_size
    return safe_count(source) == safe_count(target) and safe_logical_size(source) == safe_logical_size(target)


def symlink_points_to(source: Path, target: Path) -> bool:
    if not source.is_symlink():
        return False
    try:
        return source.resolve() == target.resolve()
    except OSError:
        return False


def run_command(args: Sequence[str]) -> None:
    result = subprocess.run(args, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        raise CommandFailure(args, result.returncode, output)


def tolerant_copytree(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copystat(source, target, follow_symlinks=False)
    except OSError:
        pass
    for root, dirs, files in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        rel = root_path.relative_to(source)
        target_root = target / rel
        target_root.mkdir(parents=True, exist_ok=True)

        kept = []
        for dirname in dirs:
            src = root_path / dirname
            dst = target_root / dirname
            if should_skip(src):
                continue
            if src.is_symlink():
                if not (dst.exists() or dst.is_symlink()):
                    os.symlink(os.readlink(src), dst)
            else:
                kept.append(dirname)
                dst.mkdir(exist_ok=True)
                try:
                    shutil.copystat(src, dst, follow_symlinks=False)
                except OSError:
                    pass
        dirs[:] = kept

        for filename in files:
            src = root_path / filename
            dst = target_root / filename
            if should_skip(src):
                continue
            if src.is_symlink():
                if not (dst.exists() or dst.is_symlink()):
                    os.symlink(os.readlink(src), dst)
            else:
                shutil.copy2(src, dst, follow_symlinks=False)


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def copy_path(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        remove_path(target)
    if source.is_dir() and not source.is_symlink():
        if sys.platform == "darwin" and shutil.which("ditto"):
            try:
                run_command(["ditto", str(source), str(target)])
                return
            except CommandFailure:
                remove_path(target)
        tolerant_copytree(source, target)
    else:
        if not should_skip(source):
            shutil.copy2(source, target, follow_symlinks=False)


def move_to_archive(source: Path, archive: Path) -> Optional[Path]:
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists() or archive.is_symlink():
        archive = archive.with_name(f"{archive.name}-{dt.datetime.now().strftime('%H%M%S')}")
    try:
        shutil.move(str(source), str(archive))
        return archive
    except Exception as exc:
        if not isinstance(exc, PermissionError) and "Operation not permitted" not in str(exc):
            raise
        fallback = source.with_name(f"{source.name}.original-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}")
        try:
            source.rename(fallback)
            return fallback
        except Exception as rename_exc:
            if not isinstance(rename_exc, PermissionError) and "Operation not permitted" not in str(rename_exc):
                raise
            return None


def read_bundle_info(app_path: Path) -> Tuple[str, str, str]:
    try:
        with (app_path / "Contents" / "Info.plist").open("rb") as f:
            info = plistlib.load(f)
        return (
            str(info.get("CFBundleIdentifier") or ""),
            str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or app_path.stem),
            str(info.get("CFBundleExecutable") or ""),
        )
    except Exception:
        return "", app_path.stem, ""


def scan_apps(volume: Optional[Path] = None) -> List[AppEntry]:
    apps: List[AppEntry] = []
    seen_paths = set()
    seen_bundles = set()

    def add_app(app_path: Path, *, already_linked: Optional[bool] = None) -> None:
        key = str(app_path.resolve()) if app_path.exists() else str(app_path)
        if key in seen_paths:
            return
        seen_paths.add(key)
        bundle_id, display_name, executable_name = read_bundle_info(app_path)
        if bundle_id and bundle_id in seen_bundles:
            return
        if bundle_id:
            seen_bundles.add(bundle_id)
        linked = app_path.is_symlink() if already_linked is None else already_linked
        apps.append(AppEntry(app_path.stem, app_path, bundle_id, display_name, executable_name, linked))

    for root in (Path("/Applications"), HOME / "Applications"):
        if not root.exists():
            continue
        for app_path in sorted(root.glob("*.app"), key=lambda p: p.name.lower()):
            add_app(app_path)

    vol = volume or DEFAULT_VOLUME
    managed_apps = vol / MANAGED_DIR_NAME / "Applications"
    if managed_apps.is_dir():
        for app_path in sorted(managed_apps.glob("*.app"), key=lambda p: p.name.lower()):
            bundle_id, _, _ = read_bundle_info(app_path)
            if bundle_id and bundle_id in seen_bundles:
                continue
            symlink_path, health = _find_symlink_for_app(bundle_id, app_path.stem)
            if symlink_path and health == "symlink":
                add_app(symlink_path, already_linked=True)
                continue
            # Tự phục hồi symlink ở /Applications nếu bị mất
            repaired = Path("/Applications") / app_path.name
            if not repaired.exists() and not repaired.is_symlink():
                try:
                    os.symlink(str(app_path), str(repaired))
                    add_app(repaired, already_linked=True)
                    continue
                except OSError:
                    pass
            add_app(app_path, already_linked=True)

    return apps


def _volume_is_writable(path: Path) -> bool:
    """Loại ổ DMG/read-only (vd. Install Discord) khỏi danh sách đích."""
    try:
        st = os.statvfs(path)
        if getattr(os, "ST_RDONLY", 0) and (st.f_flag & os.ST_RDONLY):
            return False
        return True
    except OSError:
        return False


def scan_volumes() -> List[Path]:
    volumes = []
    root = Path("/Volumes")
    if root.exists():
        for item in sorted(root.iterdir(), key=lambda p: p.name.lower()):
            if item.name.startswith(".") or item.name == "Macintosh HD":
                continue
            if item.is_dir() and _volume_is_writable(item):
                volumes.append(item)
    if DEFAULT_VOLUME.exists() and DEFAULT_VOLUME not in volumes and _volume_is_writable(DEFAULT_VOLUME):
        volumes.insert(0, DEFAULT_VOLUME)
    return volumes


def name_variants(app: AppEntry) -> List[str]:
    values = [
        app.name,
        app.display_name,
        app.executable_name,
        app.bundle_id,
        app.bundle_id.replace("-", "_"),
        app.bundle_id.replace(".", "-"),
    ]
    if app.name.endswith(" IDE"):
        values.append(app.name[:-4])
    out = []
    for value in values:
        value = (value or "").strip()
        if value and value not in out:
            out.append(value)
    return out


def candidate_sources(app: AppEntry) -> List[Path]:
    candidates: List[Path] = []

    def add(path: Path) -> None:
        if path.exists() or path.is_symlink():
            candidates.append(path)

    for name in name_variants(app):
        add(USER_LIBRARY / "Application Support" / name)
        add(USER_LIBRARY / "Caches" / name)
        add(USER_LIBRARY / "Logs" / name)

    if app.bundle_id:
        for path in (
            USER_LIBRARY / "Application Support" / app.bundle_id,
            USER_LIBRARY / "Caches" / app.bundle_id,
            USER_LIBRARY / "Containers" / app.bundle_id,
            USER_LIBRARY / "Group Containers" / f"group.{app.bundle_id}",
            USER_LIBRARY / "HTTPStorages" / app.bundle_id,
            USER_LIBRARY / "WebKit" / app.bundle_id,
            USER_LIBRARY / "Saved Application State" / f"{app.bundle_id}.savedState",
            USER_LIBRARY / "Application Scripts" / app.bundle_id,
            USER_LIBRARY / "Preferences" / f"{app.bundle_id}.plist",
        ):
            add(path)
        for base in (USER_LIBRARY / "Caches", USER_LIBRARY / "HTTPStorages"):
            if base.exists():
                for item in base.glob(f"{app.bundle_id}*"):
                    add(item)
        group_root = USER_LIBRARY / "Group Containers"
        if group_root.exists():
            for item in group_root.iterdir():
                if item.name.startswith(".") or not item.name.startswith("group."):
                    continue
                if app.bundle_id in item.name or item.name.endswith(app.bundle_id):
                    add(item)
        by_host = USER_LIBRARY / "Preferences" / "ByHost"
        if by_host.exists():
            for item in by_host.glob(f"{app.bundle_id}*.plist"):
                add(item)

    if app.bundle_id.startswith("com.docker."):
        for path in (
            USER_LIBRARY / "Application Support" / "Docker Desktop",
            USER_LIBRARY / "Application Support" / "com.docker.install",
            USER_LIBRARY / "Group Containers" / "group.com.docker",
            USER_LIBRARY / "Containers" / "com.docker.docker",
            USER_LIBRARY / "Caches" / "com.docker.docker",
        ):
            add(path)

    if app.bundle_id.startswith("com.jetbrains."):
        product = app.bundle_id.rsplit(".", 1)[-1]
        for base in (
            USER_LIBRARY / "Application Support" / "JetBrains",
            USER_LIBRARY / "Caches" / "JetBrains",
            USER_LIBRARY / "Logs" / "JetBrains",
        ):
            if base.exists():
                for item in base.glob(f"{product}*"):
                    add(item)

    pref_dir = USER_LIBRARY / "Preferences"
    if pref_dir.exists():
        needles = [v.lower().replace(" ", "") for v in name_variants(app) if len(v) >= 3]
        for item in pref_dir.glob("*.plist"):
            compact = item.stem.lower().replace(" ", "")
            if any(fnmatch.fnmatch(compact, f"*{needle}*") for needle in needles):
                add(item)

    unique = []
    seen = set()
    for path in candidates:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _data_target(managed: Path, source: Path) -> Path:
    return managed / "UserLibrary" / source.relative_to(USER_LIBRARY)


# Các vùng sandbox được macOS bảo vệ: không thể đổi tên/xóa cả thư mục gốc
# (rename/unlink → "Operation not permitted"), nhưng file/thư mục con bên trong
# (vd. Docker.raw) thường vẫn chuyển được → copy cả cây rồi symlink sâu từng phần.
PROTECTED_LIBRARY_DIRS = ("Containers", "Group Containers")
# File lớn hơn ngưỡng này: sau khi copy xong thì xóa bản Mac, không archive (tránh nhân đôi dung lượng).
LARGE_SKIP_ARCHIVE_BYTES = 100 * 1024 * 1024
# Còn dưới ngưỡng này trên Mac (không tính symlink) thì coi như đã chuyển xong.
PROTECTED_PENDING_BYTES = 1024 * 1024


def _is_protected_move_path(source: Path) -> bool:
    try:
        rel = source.relative_to(USER_LIBRARY)
    except ValueError:
        return False
    return len(rel.parts) > 0 and rel.parts[0] in PROTECTED_LIBRARY_DIRS


def _local_data_size(path: Path) -> int:
    """Dung lượng còn nằm thật trên Mac (bỏ qua symlink đã trỏ ra ngoài)."""
    try:
        if should_skip(path):
            return 0
        if path.is_symlink():
            return 0
        if path.is_file():
            st = path.stat()
            alloc = st.st_blocks * 512
            return alloc if (alloc > 0 or st.st_size == 0) else st.st_size
        total = 0
        for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
            root_path = Path(root)
            kept = []
            for name in dirs:
                item = root_path / name
                if item.is_symlink():
                    continue
                kept.append(name)
            dirs[:] = kept
            for name in files:
                item = root_path / name
                if should_skip(item) or item.is_symlink():
                    continue
                st = item.stat()
                alloc = st.st_blocks * 512
                total += alloc if (alloc > 0 or st.st_size == 0) else st.st_size
        return total
    except OSError:
        return 0


def _protected_tree_needs_move(source: Path, target: Path) -> bool:
    if not source.exists() and not source.is_symlink():
        return False
    if symlink_points_to(source, target):
        return False
    return _local_data_size(source) > PROTECTED_PENDING_BYTES


def _protected_tree_synced(source: Path, target: Path) -> bool:
    """Mọi file thật còn trên Mac đều đã có bản tương ứng đủ size trên ổ ngoài."""
    if symlink_points_to(source, target):
        return True
    if not source.exists():
        return True
    if not target.exists():
        return False
    try:
        for root, dirs, files in os.walk(source, topdown=True, followlinks=False):
            root_path = Path(root)
            kept = []
            for name in dirs:
                item = root_path / name
                if item.is_symlink():
                    continue
                kept.append(name)
            dirs[:] = kept
            for name in files:
                src = root_path / name
                if should_skip(src) or src.is_symlink():
                    continue
                dst = target / src.relative_to(source)
                if not dst.is_file():
                    return False
                if src.stat().st_size != dst.stat().st_size:
                    return False
        return True
    except OSError:
        return False


def sync_protected_tree(source: Path, target: Path, log: "JobLog") -> None:
    """Copy bổ sung các file thật trong sandbox → ổ ngoài (không xóa bản đã có trên đích)."""
    target.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copystat(source, target, follow_symlinks=False)
    except OSError:
        pass
    for root, dirs, files in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        rel = root_path.relative_to(source)
        dest_root = target / rel
        dest_root.mkdir(parents=True, exist_ok=True)
        kept = []
        for name in dirs:
            src_dir = root_path / name
            if should_skip(src_dir) or src_dir.is_symlink():
                continue
            kept.append(name)
            dst_dir = dest_root / name
            dst_dir.mkdir(exist_ok=True)
            try:
                shutil.copystat(src_dir, dst_dir, follow_symlinks=False)
            except OSError:
                pass
        dirs[:] = kept
        for name in files:
            src = root_path / name
            if should_skip(src) or src.is_symlink():
                continue
            dst = dest_root / name
            try:
                if dst.is_file() and src.stat().st_size == dst.stat().st_size:
                    continue
            except OSError:
                pass
            log.info(f"Copy file: {src} -> {dst}")
            shutil.copy2(src, dst, follow_symlinks=False)


def _replace_path_with_symlink(source: Path, target: Path, archive: Path, log: "JobLog") -> bool:
    """Sau khi đã có bản copy ở target: gỡ bản Mac và tạo symlink. True nếu thành công."""
    if symlink_points_to(source, target):
        return True
    size = 0
    try:
        if source.is_symlink():
            size = 0
        elif source.is_file():
            size = source.stat().st_size
        elif source.is_dir():
            size = _local_data_size(source)
    except OSError:
        size = 0

    if size >= LARGE_SKIP_ARCHIVE_BYTES:
        try:
            remove_path(source)
            os.symlink(str(target), str(source))
            log.info(f"Symlink goi lon (khong archive): {source} -> {target}")
            return True
        except OSError as exc:
            log.info(f"Khong the thay bang symlink: {source} ({exc})")
            return False

    archived = move_to_archive(source, archive)
    if archived is None:
        try:
            if source.is_dir() and not source.is_symlink():
                return False
            remove_path(source)
            os.symlink(str(target), str(source))
            log.info(f"Symlink (xoa ban goc): {source} -> {target}")
            return True
        except OSError as exc:
            log.info(f"Khong the symlink: {source} ({exc})")
            return False
    if archived != archive:
        log.info(f"Khong the dua ban goc sang o ngoai, da giu tai: {archived}")
    try:
        os.symlink(str(target), str(source))
        log.info(f"Symlink: {source} -> {target}")
        return True
    except OSError as exc:
        log.info(f"Da archive nhung khong tao duoc symlink: {source} ({exc})")
        return False


def deep_relocate_tree(source: Path, target: Path, archive: Path, log: "JobLog") -> None:
    """Copy đã xong: cố gắng symlink cả cây; nếu macOS chặn gốc thì đi sâu vào từng phần con."""
    if symlink_points_to(source, target):
        log.info(f"Da la symlink dung, bo qua: {source}")
        return
    if not target.exists():
        raise RuntimeError(f"Thieu ban copy tren o ngoai: {target}")

    def recurse(src: Path, dst: Path, arch: Path) -> None:
        if should_skip(src):
            return
        if symlink_points_to(src, dst):
            return
        if src.is_symlink():
            return

        if src.is_file():
            try:
                if not dst.is_file() or src.stat().st_size != dst.stat().st_size:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst, follow_symlinks=False)
            except OSError as exc:
                log.info(f"Khong copy duoc file: {src} ({exc})")
                return
            if not _replace_path_with_symlink(src, dst, arch, log):
                log.info(f"Giu tren Mac (khong doi duoc): {src}")
            return

        if not src.is_dir():
            return

        # Thử thay cả thư mục bằng 1 symlink trước
        if dst.exists() and same_data(src, dst):
            if _replace_path_with_symlink(src, dst, arch, log):
                return

        dst.mkdir(parents=True, exist_ok=True)
        try:
            children = sorted(src.iterdir(), key=lambda p: p.name.lower())
        except OSError as exc:
            log.info(f"Khong doc duoc thu muc: {src} ({exc})")
            return
        for child in children:
            recurse(child, dst / child.name, arch / child.name)

    log.info(f"Symlink sau (sandbox): {source}")
    recurse(source, target, archive)
    remaining = _local_data_size(source)
    if remaining > PROTECTED_PENDING_BYTES:
        log.info(
            f"Van con ~{human_size(remaining)} trong sandbox tren Mac "
            f"(macOS khoa mot so muc): {source}"
        )
    else:
        log.info(f"Da chuyen het du lieu nang trong sandbox: {source}")


def _needs_data_move(source: Path, target: Path) -> bool:
    if _is_protected_move_path(source):
        return _protected_tree_needs_move(source, target)
    if not source.exists() and not source.is_symlink():
        return False
    if symlink_points_to(source, target):
        return False
    if source.is_symlink():
        try:
            resolved = source.resolve()
            if resolved == target.resolve():
                return False
            managed_root = target.parent
            while managed_root.name and managed_root.name != MANAGED_DIR_NAME:
                managed_root = managed_root.parent
            if str(resolved).startswith(str(managed_root / "UserLibrary")):
                return False
        except OSError:
            return True
    return True


def pending_data_items(app: AppEntry, volume: Path) -> List[MoveItem]:
    """Các mục dữ liệu ~/Library chưa được chuyển sang UserLibrary trên ổ ngoài."""
    managed = volume / MANAGED_DIR_NAME
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = managed / "Originals" / timestamp
    items: List[MoveItem] = []
    for source in candidate_sources(app):
        target = _data_target(managed, source)
        if not _needs_data_move(source, target):
            continue
        items.append(
            MoveItem(
                source,
                target,
                archive / "Library" / source.relative_to(USER_LIBRARY),
                str(source.relative_to(USER_LIBRARY)),
            )
        )
    return items


def has_pending_data(app: AppEntry, volume: Path) -> bool:
    if not app.already_linked:
        return False
    return bool(pending_data_items(app, volume))


def build_data_plan(app: AppEntry, volume: Path) -> MovePlan:
    """Kế hoạch chỉ chuyển dữ liệu ~/Library (app .app đã ở ổ ngoài)."""
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    managed = volume / MANAGED_DIR_NAME
    items = pending_data_items(app, volume)
    if not items:
        raise RuntimeError(f"Khong co du lieu can chuyen cho {app.name}.")
    return MovePlan(app, managed, timestamp, items)


def build_plan(app: AppEntry, volume: Path) -> MovePlan:
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    managed = volume / MANAGED_DIR_NAME
    archive = managed / "Originals" / timestamp
    items = [
        MoveItem(
            app.path,
            managed / "Applications" / app.path.name,
            archive / "Applications" / app.path.name,
            "Ung dung .app",
        )
    ]
    for source in candidate_sources(app):
        items.append(
            MoveItem(
                source,
                managed / "UserLibrary" / source.relative_to(USER_LIBRARY),
                archive / "Library" / source.relative_to(USER_LIBRARY),
                str(source.relative_to(USER_LIBRARY)),
            )
        )
    return MovePlan(app, managed, timestamp, items)


def running_processes(app: AppEntry) -> List[str]:
    matches = []
    # 1. Check if the main application bundle is running using AppleScript
    try:
        cmd = ["osascript", "-e", f'application "{app.path}" is running']
        result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0 and result.stdout.strip() == "true":
            matches.append(f"Main application running: {app.name}")
    except Exception:
        pass

    # 2. Check by bundle ID using AppleScript as fallback
    if app.bundle_id:
        try:
            cmd = ["osascript", "-e", f'application id "{app.bundle_id}" is running']
            result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0 and result.stdout.strip() == "true":
                matches.append(f"Main application running (bundle ID): {app.bundle_id}")
        except Exception:
            pass

    # 3. Check for helper/sub-processes originating from the app bundle path (very specific, no substring false positives)
    app_path_str = str(app.path)
    if not app_path_str.endswith("/"):
        app_path_str += "/"
    try:
        result = subprocess.run(["pgrep", "-fl", app_path_str], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and str(os.getpid()) not in line and line not in matches:
                matches.append(line)
    except Exception:
        pass

    return matches


def quit_application(app: AppEntry, log: JobLog) -> None:
    """Đóng ứng dụng đang chạy (graceful quit, rồi force quit nếu cần)."""
    if not running_processes(app):
        return

    log.info(f"Dang dong {app.display_name or app.name}...")
    quit_scripts: List[str] = []
    seen_scripts: set = set()
    for name in (app.display_name, app.name):
        if not name:
            continue
        script = f'tell application "{name}" to quit'
        if script not in seen_scripts:
            seen_scripts.add(script)
            quit_scripts.append(script)
    if app.bundle_id:
        script = f'tell application id "{app.bundle_id}" to quit'
        if script not in seen_scripts:
            quit_scripts.append(script)

    for script in quit_scripts:
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                log.info("Da gui lenh dong ung dung.")
                break
        except Exception:
            continue

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if not running_processes(app):
            log.info(f"{app.display_name or app.name} da dong.")
            return
        time.sleep(0.5)

    log.info("Ung dung chua dong, dang force quit...")
    _force_quit_application(app, log)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not running_processes(app):
            log.info(f"{app.display_name or app.name} da force quit.")
            return
        time.sleep(0.3)

    raise RuntimeError(f"Khong the dong {app.display_name or app.name}. Hay dong thu cong roi thu lai.")


def _force_quit_application(app: AppEntry, log: JobLog) -> None:
    for name in (app.executable_name, app.name, app.display_name):
        if not name:
            continue
        result = subprocess.run(
            ["killall", name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode == 0:
            log.info(f"Force quit bang killall {name}")

    app_path_str = str(app.path)
    if not app_path_str.endswith("/"):
        app_path_str += "/"
    subprocess.run(["pkill", "-f", app_path_str], check=False)


SCAN_LOCK = threading.Lock()
SCAN_STATUS = "idle"
SCAN_PROGRESS = 0.0
SCAN_CURRENT_ITEM = ""
SCAN_SUMMARY = {}
SCAN_DETAILS = {
    "applications": [],
    "developer": [],
    "documents": [],
    "system_data": []
}


def get_scan_targets() -> Dict[str, List[Path]]:
    targets = {
        "applications": [],
        "developer": [],
        "documents": [],
        "system_data": []
    }
    
    # 1. Applications — giống macOS Settings: /Applications + ~/Applications + /System/Applications
    for root in (Path("/Applications"), Path.home() / "Applications", Path("/System/Applications")):
        if root.exists():
            try:
                for entry in root.iterdir():
                    if not entry.name.startswith("."):
                        targets["applications"].append(entry)
            except OSError:
                pass
                
    # 2. Developer
    dev_root = Path.home() / "Library/Developer"
    if dev_root.exists():
        try:
            for entry in dev_root.iterdir():
                if not entry.name.startswith("."):
                    targets["developer"].append(entry)
        except OSError:
            pass
    for path in (Path.home() / ".npm", Path.home() / ".cargo", Path.home() / ".cocoapods", Path.home() / ".gradle"):
        if path.exists():
            targets["developer"].append(path)
            
    # 3. Documents — scan toàn bộ home directory ngoại trừ Library
    # Giống macOS Settings: "Documents" = tất cả file/folder người dùng tạo ra
    # (bao gồm Movies, Music, Pictures, code projects, Downloads, Desktop, v.v.)
    _LIBRARY_EXCL = {"Library"}
    home = Path.home()
    try:
        for entry in home.iterdir():
            if not entry.name.startswith(".") and entry.name not in _LIBRARY_EXCL:
                targets["documents"].append(entry)
    except OSError:
        pass
                
    # 4. System Data — mở rộng giống macOS Settings
    # Các folder được scan theo từng sub-entry (để có chi tiết từng item)
    for folder in (
        "Library/Application Support",
        "Library/Caches",
        "Library/Containers",
        "Library/Logs",
        "Library/Group Containers",
        "Library/HTTPStorages",
        "Library/WebKit",
        "Library/Saved Application State",
    ):
        root = Path.home() / folder
        if root.exists():
            try:
                for entry in root.iterdir():
                    if not entry.name.startswith("."):
                        targets["system_data"].append(entry)
            except OSError:
                pass

    # Preferences folder — thêm cả folder (không iterate sub-entry vì quá nhiều .plist nhỏ)
    prefs = Path.home() / "Library/Preferences"
    if prefs.exists():
        targets["system_data"].append(prefs)

    return targets



def scan_storage_task() -> None:
    global SCAN_STATUS, SCAN_PROGRESS, SCAN_CURRENT_ITEM, SCAN_SUMMARY, SCAN_DETAILS
    with SCAN_LOCK:
        if SCAN_STATUS == "scanning":
            return
        SCAN_STATUS = "scanning"
        SCAN_PROGRESS = 0.0
        SCAN_CURRENT_ITEM = "Chuẩn bị quét..."
        SCAN_SUMMARY = {}
        SCAN_DETAILS = {
            "applications": [],
            "developer": [],
            "documents": [],
            "system_data": []
        }

    try:
        targets = get_scan_targets()
        
        # Count total items to calculate progress
        total_items = sum(len(items) for items in targets.values())
        if total_items == 0:
            total_items = 1
            
        scanned_count = 0
        category_totals = {
            "applications": 0,
            "developer": 0,
            "documents": 0,
            "system_data": 0
        }
        
        # Scan applications
        for item in targets["applications"]:
            with SCAN_LOCK:
                SCAN_CURRENT_ITEM = f"Quét Ứng dụng: {item.name}"
                SCAN_PROGRESS = scanned_count / total_items
            size = du_size(item)
            category_totals["applications"] += size
            SCAN_DETAILS["applications"].append({
                "name": item.name,
                "path": str(item),
                "size": size,
                "size_human": human_size(size)
            })
            scanned_count += 1
            
        # Scan developer
        for item in targets["developer"]:
            with SCAN_LOCK:
                SCAN_CURRENT_ITEM = f"Quét Developer: {item.name}"
                SCAN_PROGRESS = scanned_count / total_items
            size = du_size(item)
            category_totals["developer"] += size
            label = item.name
            if item.name.startswith("."):
                label = f"~/{item.name}"
            elif item.is_relative_to(Path.home() / "Library/Developer"):
                label = f"Developer/{item.name}"
            SCAN_DETAILS["developer"].append({
                "name": label,
                "path": str(item),
                "size": size,
                "size_human": human_size(size)
            })
            scanned_count += 1

        # Scan documents
        for item in targets["documents"]:
            with SCAN_LOCK:
                SCAN_CURRENT_ITEM = f"Quét Documents/Downloads: {item.name}"
                SCAN_PROGRESS = scanned_count / total_items
            size = du_size(item)
            category_totals["documents"] += size
            SCAN_DETAILS["documents"].append({
                "name": f"{item.parent.name}/{item.name}",
                "path": str(item),
                "size": size,
                "size_human": human_size(size)
            })
            scanned_count += 1

        # Scan system data
        for item in targets["system_data"]:
            with SCAN_LOCK:
                SCAN_CURRENT_ITEM = f"Quét Thư viện: {item.name}"
                SCAN_PROGRESS = scanned_count / total_items
            size = du_size(item)
            category_totals["system_data"] += size
            SCAN_DETAILS["system_data"].append({
                "name": f"Library/{item.parent.name}/{item.name}" if item.parent.name != "Library" else f"Library/{item.name}",
                "path": str(item),
                "size": size,
                "size_human": human_size(size)
            })
            scanned_count += 1

        # Sort all details lists by size descending
        for cat in SCAN_DETAILS:
            SCAN_DETAILS[cat].sort(key=lambda x: x["size"], reverse=True)

        # Get total system disk sizes — dùng APFS container info để khớp với macOS Settings
        total_disk, used_disk, free_disk = get_apfs_disk_info()
        
        # Calculate macOS / Other category size
        sum_scanned = sum(category_totals.values())
        macos_size = max(0, used_disk - sum_scanned)
        category_totals["macos"] = macos_size
        category_totals["free"] = free_disk
        category_totals["total"] = total_disk
        category_totals["used"] = used_disk
        
        # Store summary with human-readable values
        SCAN_SUMMARY = {
            "total": total_disk,
            "total_human": human_size(total_disk),
            "used": used_disk,
            "used_human": human_size(used_disk),
            "free": free_disk,
            "free_human": human_size(free_disk),
            "categories": {
                "applications": {
                    "label": "Applications",
                    "size": category_totals["applications"],
                    "size_human": human_size(category_totals["applications"]),
                    "color": "#eab308"
                },
                "developer": {
                    "label": "Developer",
                    "size": category_totals["developer"],
                    "size_human": human_size(category_totals["developer"]),
                    "color": "#f97316"
                },
                "documents": {
                    "label": "Documents",
                    "size": category_totals["documents"],
                    "size_human": human_size(category_totals["documents"]),
                    "color": "#ef4444"
                },
                "system_data": {
                    "label": "System Data",
                    "size": category_totals["system_data"],
                    "size_human": human_size(category_totals["system_data"]),
                    "color": "#6b7280"
                },
                "macos": {
                    "label": "macOS",
                    "size": category_totals["macos"],
                    "size_human": human_size(category_totals["macos"]),
                    "color": "#9ca3af"
                }
            }
        }
        
        with SCAN_LOCK:
            SCAN_STATUS = "done"
            SCAN_PROGRESS = 1.0
            SCAN_CURRENT_ITEM = "Quá trình quét hoàn tất."
            
    except Exception as exc:
        with SCAN_LOCK:
            SCAN_STATUS = "error"
            SCAN_CURRENT_ITEM = f"Lỗi quét: {str(exc)}"


def start_background_scan() -> None:
    threading.Thread(target=scan_storage_task, daemon=True).start()


class JobLog:
    def __init__(self, job_id: str) -> None:
        self.job_id = job_id

    def _write(self, text: str, status: Optional[str] = None) -> None:
        with JOBS_LOCK:
            job = JOBS[self.job_id]
            job["logs"].append(text)
            job["status_text"] = text
            if status:
                job["status"] = status

    def info(self, text: str) -> None:
        self._write(text)

    def done(self, text: str) -> None:
        self._write(text, "done")

    def error(self, text: str) -> None:
        self._write(text, "error")


def process_plan(plan: MovePlan, log: JobLog) -> None:
    quit_application(plan.app, log)
    if running_processes(plan.app):
        raise RuntimeError(f"Hay dong {plan.app.name} truoc khi chuyen.")
    plan.managed_root.mkdir(parents=True, exist_ok=True)
    pending = [item for item in plan.items if _needs_data_move(item.source, item.target)]
    if not pending:
        log.done("Khong co muc nao can chuyen.")
        return
    total = 0
    for item in pending:
        if _is_protected_move_path(item.source):
            total += _local_data_size(item.source)
        else:
            total += safe_size(item.source)
    data_only = all(str(item.source).startswith(str(USER_LIBRARY)) for item in pending)
    if data_only:
        log.info(f"Chuyen du lieu {plan.app.name} sang {plan.managed_root.parent} ({human_size(total)}).")
    else:
        log.info(f"Chuyen {plan.app.name} sang {plan.managed_root.parent} ({human_size(total)}).")

    for i, item in enumerate(pending, 1):
        log.info(f"Dang copy {i}/{len(pending)}: {item.label}")
        if symlink_points_to(item.source, item.target):
            log.info(f"Da la symlink dung, bo qua copy: {item.source}")
        elif _is_protected_move_path(item.source):
            if item.target.exists() and _protected_tree_synced(item.source, item.target):
                log.info(f"Dich da co du (sandbox), bo qua copy: {item.target}")
            else:
                log.info(f"Dong bo sandbox: {item.source} -> {item.target}")
                sync_protected_tree(item.source, item.target, log)
            if not _protected_tree_synced(item.source, item.target):
                raise RuntimeError(f"Kiem tra sau copy sandbox that bai: {item.source}")
        elif item.target.exists() and same_data(item.source, item.target):
            log.info(f"Dich da co du, bo qua copy: {item.target}")
        else:
            if item.target.exists() and str(item.target).startswith(str(plan.managed_root)):
                log.info(f"Xoa ban copy do de copy lai sach: {item.target}")
                remove_path(item.target)
            log.info(f"Copy: {item.source} -> {item.target}")
            copy_path(item.source, item.target)
            if not symlink_points_to(item.source, item.target) and not same_data(item.source, item.target):
                raise RuntimeError(f"Kiem tra sau copy that bai: {item.source}")

    manifest_dir = plan.managed_root / "Manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "app": plan.app.name,
        "bundle_id": plan.app.bundle_id,
        "timestamp": plan.timestamp,
        "items": [{"source": str(i.source), "target": str(i.target), "archive": str(i.original_archive), "label": i.label} for i in pending],
    }
    suffix = f"{plan.app.name}-data" if data_only else plan.app.name
    manifest_path = manifest_dir / f"{suffix}-{plan.timestamp}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    for i, item in enumerate(pending, 1):
        log.info(f"Dang tao symlink {i}/{len(pending)}: {item.label}")
        if symlink_points_to(item.source, item.target):
            log.info(f"Da la symlink dung, bo qua: {item.source}")
            continue
        if _is_protected_move_path(item.source):
            deep_relocate_tree(item.source, item.target, item.original_archive, log)
            continue
        if not _replace_path_with_symlink(item.source, item.target, item.original_archive, log):
            log.info(f"macOS chan rename/move muc nay. Da copy sang o ngoai nhung muc dang dung van o Mac: {item.source}")
    log.done(f"Xong. Manifest: {manifest_path}")


def _temp_scan_roots() -> List[Path]:
    roots: List[Path] = []
    seen: set = set()
    import tempfile

    for candidate in (os.environ.get("TMPDIR"), str(Path.home() / "Library" / "Caches"), tempfile.gettempdir()):
        if not candidate:
            continue
        root = Path(candidate)
        try:
            key = str(root.resolve())
        except OSError:
            key = str(root)
        if key in seen or not root.is_dir():
            continue
        seen.add(key)
        roots.append(root)
    return roots


def _stuck_dir_kind(name: str) -> Optional[str]:
    if name.startswith("com.") and ".ShipIt" in name:
        return "squirrel"
    if re.fullmatch(r".+-update-.+", name):
        return "sparkle"
    return None


def _stuck_temp_dirs() -> List[Tuple[Path, str]]:
    """Trả về (thư mục temp/cache, loại update) cho Squirrel ShipIt hoặc Sparkle."""
    candidates: List[Tuple[Path, str]] = []
    seen: set = set()
    for root in _temp_scan_roots():
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not (child.is_dir() or child.is_symlink()):
                continue
            kind = _stuck_dir_kind(child.name)
            if not kind:
                continue
            key = str(child)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((child, kind))
    return candidates


def _is_mount_point(path: Path) -> bool:
    try:
        st = os.stat(path)
        parent_st = os.stat(path.parent)
        return st.st_dev != parent_st.st_dev
    except OSError:
        return False


def _detach_mount(mount_point: Path) -> None:
    mount_point = mount_point.resolve()
    if not _is_mount_point(mount_point):
        return
    for cmd in (
        ["diskutil", "eject", str(mount_point)],
        ["hdiutil", "detach", str(mount_point), "-quiet"],
        ["hdiutil", "detach", str(mount_point), "-force", "-quiet"],
    ):
        result = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if result.returncode == 0:
            return
    if _is_mount_point(mount_point):
        raise RuntimeError(f"Khong go bo duoc mount Sparkle: {mount_point}")


def _cleanup_sparkle_staging(temp_dir: Path, app_stem: str, log: JobLog) -> None:
    if _is_mount_point(temp_dir):
        log.info(f"Go bo mount Sparkle: {temp_dir}")
        _detach_mount(temp_dir)

    tmp_root = temp_dir.parent
    stem_lower = app_stem.lower()
    for child in tmp_root.iterdir():
        name_lower = child.name.lower()
        if child.is_file() and "-updater-" in name_lower and name_lower.endswith(".sh"):
            if stem_lower in name_lower or name_lower.startswith(f"{stem_lower}-updater-"):
                log.info(f"Xoa script updater: {child}")
                remove_path(child)

    stray = tmp_root / app_stem
    if stray.is_dir():
        try:
            if not any(stray.iterdir()):
                log.info(f"Xoa thu muc tam trong: {stray}")
                remove_path(stray)
        except OSError:
            pass

    if temp_dir.exists():
        try:
            if not _is_mount_point(temp_dir):
                log.info(f"Xoa thu muc Sparkle: {temp_dir}")
                remove_path(temp_dir)
        except OSError:
            pass


class ScanRecoverLog:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def info(self, text: str) -> None:
        self.lines.append(text)

    def done(self, text: str) -> None:
        self.lines.append(text)

    def error(self, text: str) -> None:
        self.lines.append(f"Loi: {text}")


def _resolve_stuck_install(
    volume: Path,
    bundle_id: str,
    app_name: str,
    app_path: Path,
    by_bundle_managed: Dict[str, Tuple[AppEntry, Path]],
    by_bundle_all: Dict[str, AppEntry],
    *,
    sparkle: bool,
) -> Tuple[Path, Optional[Path], str, str]:
    """Trả về (target, symlink_path, symlink_health, recovery_mode)."""
    if bundle_id in by_bundle_managed:
        entry, target_path = by_bundle_managed[bundle_id]
        symlink_path, symlink_health = _find_symlink_for_app(bundle_id, entry.name)
        return target_path, symlink_path, symlink_health, "razer"

    if bundle_id in by_bundle_all:
        app = by_bundle_all[bundle_id]
        if sparkle and not app.already_linked and not app.path.is_symlink():
            health = "local"
            return app.path, app.path, health, "in_place"
        target = volume / MANAGED_DIR_NAME / "Applications" / app.path.name
        health = "local" if not app.path.is_symlink() else "symlink"
        return target, app.path, health, "razer"

    target = volume / MANAGED_DIR_NAME / "Applications" / app_path.name
    symlink_path: Optional[Path] = None
    symlink_health = "missing"
    for parent in (Path("/Applications"), Path.home() / "Applications"):
        guess = parent / app_path.name
        if guess.exists() or guess.is_symlink():
            symlink_path = guess
            symlink_health = "local" if not guess.is_symlink() else "symlink"
            break
    if sparkle:
        install_path = symlink_path or (Path("/Applications") / app_path.name)
        return install_path, install_path, symlink_health, "in_place"
    if not symlink_path:
        symlink_path = Path("/Applications") / app_path.name
    return target, symlink_path, symlink_health, "razer"


def _stuck_app_in_dir(temp_dir: Path) -> Optional[Path]:
    """Tìm bundle `.app` nằm trong thư mục ShipIt hoặc trong thư mục con `update.*` của nó."""
    try:
        # Resolve symlink if needed
        resolved_dir = temp_dir.resolve() if temp_dir.is_symlink() else temp_dir
        if not resolved_dir.is_dir():
            return None
            
        # 1. Quét trực tiếp trong thư mục ShipIt
        for child in resolved_dir.iterdir():
            if child.suffix.lower() == ".app" and child.exists() and not child.is_symlink():
                return child
                
        # 2. Quét sâu hơn trong các thư mục con update.* (định dạng Stage của Squirrel)
        for child in resolved_dir.iterdir():
            if child.is_dir() and child.name.startswith("update."):
                for subchild in child.iterdir():
                    if subchild.suffix.lower() == ".app" and subchild.exists() and not subchild.is_symlink():
                        return subchild
    except OSError:
        pass
    return None


def _managed_app_entries(volume: Path) -> List[Tuple[AppEntry, Path]]:
    """Lấy danh sách app do App Mover quản lý trên ổ `volume`.

    Trả về list các tuple (AppEntry, target_path), trong đó:
      - target_path: bundle thật trên ổ ngoài
      - entry.path: symlink ở ngoài (nếu còn) — dùng để kiểm tra sức khỏe
    """
    managed_root = volume / MANAGED_DIR_NAME
    apps_root = managed_root / "Applications"
    if not apps_root.is_dir():
        return []
    result: List[Tuple[AppEntry, Path]] = []
    for app_path in sorted(apps_root.iterdir(), key=lambda p: p.name.lower()):
        if app_path.suffix.lower() != ".app":
            continue
        try:
            bundle_id, display_name, executable_name = read_bundle_info(app_path)
        except Exception:
            bundle_id, display_name, executable_name = "", app_path.stem, ""
        entry = AppEntry(
            app_path.stem,
            app_path,
            bundle_id,
            display_name or app_path.stem,
            executable_name,
            True,
        )
        result.append((entry, app_path))
    return result


def _find_symlink_for_app(bundle_id: str, app_name: str) -> Tuple[Optional[Path], str]:
    """Tìm symlink còn sống cho app `bundle_id` ở các vị trí thường gặp."""
    candidates = (
        Path("/Applications") / f"{app_name}.app",
        HOME / "Applications" / f"{app_name}.app",
    )
    for candidate in candidates:
        try:
            if candidate.is_symlink():
                return candidate, "symlink"
            if candidate.exists():
                return candidate, "local"
        except OSError:
            continue
    return None, "missing"


def scan_stuck_updates(volume: Path, auto_recover_sparkle: bool = True) -> Dict[str, object]:
    """Quét bản cập nhật Squirrel/Sparkle bị kẹt; Sparkle được tự khôi phục khi quét."""
    managed = _managed_app_entries(volume)
    by_bundle_managed = {
        entry.bundle_id: (entry, target) for entry, target in managed if entry.bundle_id
    }

    all_apps = scan_apps()
    by_bundle_all = {
        app.bundle_id: app for app in all_apps if app.bundle_id
    }

    items: List[Dict[str, object]] = []
    recovered: List[Dict[str, object]] = []
    recover_logs: List[str] = []
    seen: set = set()
    for temp_dir, update_kind in _stuck_temp_dirs():
        app_path = _stuck_app_in_dir(temp_dir)
        if not app_path:
            continue
        bundle_id, display_name, executable_name = read_bundle_info(app_path)
        if not bundle_id:
            continue

        if app_path in seen:
            continue
        seen.add(app_path)

        target, symlink_path, symlink_health, recovery_mode = _resolve_stuck_install(
            volume,
            bundle_id,
            app_path.stem,
            app_path,
            by_bundle_managed,
            by_bundle_all,
            sparkle=update_kind == "sparkle",
        )

        try:
            target_exists = target.exists() or target.is_symlink()
        except OSError:
            target_exists = False

        target_size = safe_logical_size(target) if target_exists else 0

        size = safe_logical_size(app_path)
        try:
            temp_mtime = dt.datetime.fromtimestamp(app_path.stat().st_mtime)
        except OSError:
            temp_mtime = dt.datetime.now()

        entry: Dict[str, object] = {
            "temp_dir": str(temp_dir),
            "stuck_path": str(app_path),
            "bundle_id": bundle_id,
            "app_name": app_path.stem,
            "display_name": display_name or app_path.stem,
            "executable_name": executable_name,
            "size": size,
            "size_human": human_size(size),
            "target_path": str(target),
            "target_exists": target_exists,
            "target_size": target_size,
            "target_size_human": human_size(target_size),
            "symlink_path": str(symlink_path) if symlink_path else None,
            "symlink_health": symlink_health,
            "temp_mtime": temp_mtime.isoformat(timespec="seconds"),
            "update_kind": update_kind,
            "recovery_mode": recovery_mode,
        }

        if update_kind == "sparkle" and auto_recover_sparkle:
            log = ScanRecoverLog()
            try:
                recover_sparkle_stuck_update(volume, str(temp_dir), log)
                entry["auto_recovered"] = True
                recovered.append(entry)
                recover_logs.extend(log.lines)
            except Exception as exc:
                entry["recover_error"] = str(exc)
                recover_logs.append(f"Loi khoi phuc {display_name or app_path.stem}: {exc}")
                items.append(entry)
        else:
            items.append(entry)

    items.sort(key=lambda r: str(r["app_name"]).lower())
    recovered.sort(key=lambda r: str(r["app_name"]).lower())
    return {"items": items, "recovered": recovered, "recover_logs": recover_logs}


def recover_sparkle_stuck_update(volume: Path, temp_dir_str: str, log: JobLog) -> None:
    """Khôi phục bản cập nhật Sparkle bị kẹt (Stats, …): cài bản mới và gỡ mount DMG."""
    temp_dir = Path(temp_dir_str)
    app_path = _stuck_app_in_dir(temp_dir)
    if not app_path:
        raise RuntimeError(f"Khong tim thay ban cap nhat trong: {temp_dir}")
    bundle_id, display_name, _ = read_bundle_info(app_path)
    if not bundle_id:
        raise RuntimeError(f"Khong doc duoc bundle_id cua: {app_path}")

    managed = _managed_app_entries(volume)
    by_bundle_managed = {
        entry.bundle_id: (entry, target) for entry, target in managed if entry.bundle_id
    }
    by_bundle_all = {
        app.bundle_id: app for app in scan_apps() if app.bundle_id
    }
    target, symlink_path, _, recovery_mode = _resolve_stuck_install(
        volume,
        bundle_id,
        app_path.stem,
        app_path,
        by_bundle_managed,
        by_bundle_all,
        sparkle=True,
    )

    log.info(f"Tim thay ban cap nhat Sparkle bi ket: {app_path}")
    backup_root = volume / MANAGED_DIR_NAME / "StuckUpdateBackups" / dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    if recovery_mode == "in_place":
        install_path = target
        log.info(f"Cai ban moi tai: {install_path}")
        if install_path.exists() or install_path.is_symlink():
            log.info(f"Backup ban cu: {install_path}")
            archived = move_to_archive(install_path, backup_root / "Originals" / install_path.name)
            if archived is None:
                raise RuntimeError(f"macOS khong cho backup: {install_path}")
        staging = install_path.with_name(f".{install_path.name}.sparkle-{uuid.uuid4().hex[:8]}")
        log.info(f"Copy qua staging: {staging}")
        copy_path(app_path, staging)
        if not same_data(app_path, staging):
            remove_path(staging)
            raise RuntimeError(f"Kiem tra staging that bai: {staging}")
        staging.rename(install_path)
        if not same_data(app_path, install_path):
            raise RuntimeError(f"Kiem tra sau recover that bai: {install_path}")
    else:
        log.info(f"Copy ve o Razer: {app_path} -> {target}")
        if target.exists() or target.is_symlink():
            log.info(f"Da co ban cu tren o Razer, backup: {target}")
            archived = move_to_archive(target, backup_root / "Applications" / target.name)
            if archived is None:
                raise RuntimeError(f"macOS khong cho backup: {target}")
        staging = target.with_name(f".{target.name}.sparkle-{uuid.uuid4().hex[:8]}")
        log.info(f"Copy qua staging: {staging}")
        copy_path(app_path, staging)
        if not same_data(app_path, staging):
            remove_path(staging)
            raise RuntimeError(f"Kiem tra staging that bai: {staging}")
        staging.rename(target)
        if not same_data(app_path, target):
            raise RuntimeError(f"Kiem tra sau recover that bai: {target}")
        if symlink_path and symlink_path.exists() and not symlink_path.is_symlink():
            log.info(f"Backup app goc tren Mac: {symlink_path}")
            archived = move_to_archive(symlink_path, backup_root / "Originals" / symlink_path.name)
            if archived is None:
                raise RuntimeError(f"macOS khong cho backup app goc: {symlink_path}")
        if symlink_path:
            if symlink_path.is_symlink() or symlink_path.exists():
                remove_path(symlink_path)
            log.info(f"Tao symlink lien ket: {symlink_path} -> {target}")
            os.symlink(str(target), str(symlink_path))

    _cleanup_sparkle_staging(temp_dir, app_path.stem, log)
    log.done(
        f"Khoi phuc {display_name or app_path.stem} thanh cong. "
        f"Ban cap nhat Sparkle da duoc cai va mount tam da duoc go bo."
    )


def recover_stuck_update(volume: Path, temp_dir_str: str, log: JobLog) -> None:
    """Khôi phục bản cập nhật bị kẹt (Squirrel hoặc Sparkle)."""
    temp_dir = Path(temp_dir_str)
    kind = _stuck_dir_kind(temp_dir.name)
    if kind == "sparkle":
        recover_sparkle_stuck_update(volume, temp_dir_str, log)
        return

    app_path = _stuck_app_in_dir(temp_dir)
    if not app_path:
        raise RuntimeError(f"Khong tim thay ban cap nhat trong: {temp_dir}")
    bundle_id, _, _ = read_bundle_info(app_path)
    if not bundle_id:
        raise RuntimeError(f"Khong doc duoc bundle_id cua: {app_path}")

    managed = _managed_app_entries(volume)
    by_bundle_managed = {
        entry.bundle_id: (entry, target) for entry, target in managed if entry.bundle_id
    }
    by_bundle_all = {
        app.bundle_id: app for app in scan_apps() if app.bundle_id
    }
    target, symlink_path, _, _ = _resolve_stuck_install(
        volume,
        bundle_id,
        app_path.stem,
        app_path,
        by_bundle_managed,
        by_bundle_all,
        sparkle=False,
    )

    log.info(f"Tim thay ban cap nhat bi ket: {app_path}")
    log.info(f"Copy ve o Razer: {app_path} -> {target}")

    backup_root = volume / MANAGED_DIR_NAME / "StuckUpdateBackups" / dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    if target.exists() or target.is_symlink():
        log.info(f"Da co ban cu tren o Razer, backup: {target}")
        archived = move_to_archive(target, backup_root / "Applications" / target.name)
        if archived is None:
            raise RuntimeError(f"macOS khong cho backup: {target}")

    staging = target.with_name(f".{target.name}.stuck-{uuid.uuid4().hex[:8]}")
    log.info(f"Copy qua staging: {staging}")
    copy_path(app_path, staging)
    if not same_data(app_path, staging):
        remove_path(staging)
        raise RuntimeError(f"Kiem tra staging that bai: {staging}")
    staging.rename(target)
    if not same_data(app_path, target):
        raise RuntimeError(f"Kiem tra sau recover that bai: {target}")

    if symlink_path and symlink_path.exists() and not symlink_path.is_symlink():
        log.info(f"Backup app goc tren Mac: {symlink_path}")
        archived = move_to_archive(symlink_path, backup_root / "Originals" / symlink_path.name)
        if archived is None:
            raise RuntimeError(f"macOS khong cho backup app goc: {symlink_path}")

    if symlink_path:
        if symlink_path.is_symlink() or symlink_path.exists():
            remove_path(symlink_path)
        log.info(f"Tao symlink lien ket: {symlink_path} -> {target}")
        os.symlink(str(target), str(symlink_path))

    log.info(f"Xoa thu muc ShipIt bi ket: {temp_dir}")
    remove_path(temp_dir)
    log.done("Khoi phuc va di chuyen sang Razer thanh cong. App se tu nhan ban moi lan mo.")


def delete_stuck_update(temp_dir_str: str, log: JobLog) -> None:
    """Xóa bản cập nhật bị kẹt trong temp mà không cài/khôi phục."""
    temp_dir = Path(temp_dir_str)
    kind = _stuck_dir_kind(temp_dir.name)
    if not kind:
        raise RuntimeError(f"Khong phai thu muc cap nhat bi ket: {temp_dir}")

    allowed = False
    try:
        resolved = temp_dir.resolve()
    except OSError:
        resolved = temp_dir
    for root in _temp_scan_roots():
        try:
            resolved.relative_to(root.resolve())
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        raise RuntimeError(f"Duong dan khong hop le: {temp_dir}")

    app_path = _stuck_app_in_dir(temp_dir)
    display = app_path.stem if app_path else temp_dir.name
    log.info(f"Xoa ban cap nhat bi ket: {display} ({temp_dir})")

    if kind == "sparkle":
        app_stem = app_path.stem if app_path else temp_dir.name.split("-update-", 1)[0]
        _cleanup_sparkle_staging(temp_dir, app_stem, log)
    elif temp_dir.exists() or temp_dir.is_symlink():
        log.info(f"Xoa thu muc ShipIt: {temp_dir}")
        remove_path(temp_dir)

    if kind == "squirrel" and (temp_dir.exists() or temp_dir.is_symlink()):
        raise RuntimeError(f"Khong the xoa: {temp_dir}")
    if kind == "sparkle" and temp_dir.exists() and _is_mount_point(temp_dir):
        raise RuntimeError(f"Khong the go bo mount: {temp_dir}")

    log.done(f"Da xoa ban cap nhat bi ket cua {display}. App hien tai khong thay doi.")


def find_app(path: str, volume: Optional[Path] = None) -> AppEntry:
    wanted = Path(path)
    for app in scan_apps(volume):
        if app.path == wanted:
            return app
    # Cho phép chọn trực tiếp bundle trên ổ ngoài
    if wanted.suffix.lower() == ".app" and (wanted.exists() or wanted.is_symlink()):
        bundle_id, display_name, executable_name = read_bundle_info(wanted)
        linked = wanted.is_symlink() or MANAGED_DIR_NAME in wanted.parts
        return AppEntry(wanted.stem, wanted, bundle_id, display_name, executable_name, linked)
    raise RuntimeError(f"Khong tim thay app: {path}")


def app_json(app: AppEntry, volume: Optional[Path] = None) -> Dict[str, object]:
    vol = volume or DEFAULT_VOLUME
    pending = pending_data_items(app, vol) if app.already_linked else []
    return {
        "name": app.name,
        "path": str(app.path),
        "bundle_id": app.bundle_id,
        "display_name": app.display_name,
        "already_linked": app.already_linked,
        "has_pending_data": bool(pending),
        "pending_data_count": len(pending),
    }


def _plan_preview_items(plan: MovePlan) -> Tuple[List[Dict[str, object]], int]:
    items: List[Dict[str, object]] = []
    total = 0
    for item in plan.items:
        linked = not _needs_data_move(item.source, item.target)
        if linked:
            size = 0
        elif _is_protected_move_path(item.source):
            size = _local_data_size(item.source)
        else:
            size = safe_size(item.source)
        total += size
        items.append(
            {
                "label": item.label,
                "source": str(item.source),
                "target": str(item.target),
                "size_human": human_size(size),
                "already_linked": linked,
                "protected": _is_protected_move_path(item.source),
            }
        )
    return items, total


def preview_json(plan: MovePlan) -> Dict[str, object]:
    items, total = _plan_preview_items(plan)
    return {
        "target_root": str(plan.managed_root),
        "count": len(items),
        "pending_count": sum(1 for i in items if not i["already_linked"]),
        "total_size_human": human_size(total),
        "items": items,
    }


def preview_data_json(app: AppEntry, volume: Path) -> Dict[str, object]:
    plan = build_data_plan(app, volume)
    payload = preview_json(plan)
    payload["data_only"] = True
    payload["library_root"] = str(plan.managed_root / "UserLibrary")
    return payload


def scan_app_related_files(app: AppEntry) -> List[Dict[str, object]]:
    """Quét tất cả file/folder liên quan đến app: .app bundle + data trong ~/Library."""
    results = []

    def add_entry(path: Path, category: str) -> None:
        size = du_size(path)
        results.append({
            "path": str(path),
            "name": path.name,
            "category": category,
            "size": size,
            "size_human": human_size(size),
            "is_symlink": path.is_symlink(),
            "symlink_target": str(path.resolve()) if path.is_symlink() else None,
        })

    # 1. App bundle itself
    if app.path.exists() or app.path.is_symlink():
        add_entry(app.path, "App Bundle")

    # 2. All candidate related files (Library/*)
    for src in candidate_sources(app):
        add_entry(src, _library_category(src))

    # Sort: app bundle first, then by size desc
    results.sort(key=lambda x: (0 if x["category"] == "App Bundle" else 1, -x["size"]))
    return results


def _library_category(path: Path) -> str:
    """Trả về tên danh mục thân thiện cho đường dẫn trong ~/Library."""
    parts = path.parts
    for i, part in enumerate(parts):
        if part == "Library" and i + 1 < len(parts):
            sub = parts[i + 1]
            mapping = {
                "Application Support": "Dữ liệu ứng dụng",
                "Caches": "Cache",
                "Containers": "Container",
                "Logs": "Logs",
                "Preferences": "Cài đặt",
                "Saved Application State": "Trạng thái",
                "HTTPStorages": "HTTP Storage",
                "WebKit": "WebKit",
                "Application Scripts": "Scripts",
            }
            return mapping.get(sub, f"Library/{sub}")
    return "Khác"


def delete_app_files(paths_to_delete: List[str]) -> List[Dict[str, object]]:
    """Xóa danh sách file/folder. Trả về kết quả từng mục."""
    results = []
    for path_str in paths_to_delete:
        path = Path(path_str)
        try:
            if path.is_symlink():
                # Chỉ xóa symlink, không follow vào target trên external drive
                path.unlink()
                results.append({"path": path_str, "ok": True, "note": "symlink removed"})
            elif path.is_dir():
                shutil.rmtree(str(path))
                results.append({"path": path_str, "ok": True, "note": "directory removed"})
            elif path.exists():
                path.unlink()
                results.append({"path": path_str, "ok": True, "note": "file removed"})
            else:
                results.append({"path": path_str, "ok": False, "note": "not found"})
        except Exception as exc:
            results.append({"path": path_str, "ok": False, "note": str(exc)})
    return results


# ===================== TAB: DỌN Ổ MAC (cache cleaner) =====================
# Tab này CHỈ quét/xóa trên ổ Mac (HOME + /Library/Caches...), không đụng tới
# ổ ngoài Razer — khác với tab "Chuyển Ứng Dụng" (di chuyển) và "Gỡ Ứng Dụng".

TRASH_DIR = HOME / ".Trash"


@dataclass(frozen=True)
class CleanRule:
    id: str
    category: str
    label: str
    path: Path
    description: str
    risk: str  # "safe" (tự tạo lại, xóa vô tư) | "caution" (mất dữ liệu thật, hỏi kỹ trước khi xóa)


def _cleaner_rules() -> List[CleanRule]:
    return [
        CleanRule("xcode-derived-data", "Xcode", "DerivedData",
                  HOME / "Library/Developer/Xcode/DerivedData",
                  "Cache build của Xcode. Tự tạo lại khi build lại project, xóa vô tư.", "safe"),
        CleanRule("xcode-device-support", "Xcode", "iOS DeviceSupport",
                  HOME / "Library/Developer/Xcode/iOS DeviceSupport",
                  "File symbol cho các phiên bản iOS đã từng debug qua thiết bị thật. Tự tải lại khi cắm lại máy.", "safe"),
        CleanRule("xcode-archives", "Xcode", "Archives (.xcarchive)",
                  HOME / "Library/Developer/Xcode/Archives",
                  "Bản build đã archive để nộp App Store / lưu dSYM. KHÔNG tự tạo lại — chỉ xóa nếu chắc chắn không cần.", "caution"),
        CleanRule("core-simulator-caches", "Xcode", "CoreSimulator Caches",
                  HOME / "Library/Developer/CoreSimulator/Caches",
                  "Cache runtime của iOS Simulator, xóa vô tư.", "safe"),
        CleanRule("gradle-caches", "Android / Java", "Gradle caches",
                  HOME / ".gradle/caches",
                  "Cache build Gradle (Android Studio). Lần build sau sẽ chậm hơn lần đầu, không mất project.", "safe"),
        CleanRule("npm-cache", "Node.js", "npm cache",
                  HOME / ".npm",
                  "Cache tải package của npm/npx, tự tải lại khi cần.", "safe"),
        CleanRule("yarn-cache", "Node.js", "Yarn cache",
                  HOME / "Library/Caches/Yarn",
                  "Cache tải package của Yarn, tự tải lại khi cần.", "safe"),
        CleanRule("pnpm-store", "Node.js", "pnpm store",
                  HOME / "Library/pnpm/store",
                  "Store package của pnpm, tự tải lại khi cần.", "safe"),
        CleanRule("bun-cache", "Node.js", "Bun install cache",
                  HOME / ".bun/install/cache",
                  "Cache tải package của Bun, tự tải lại khi cần.", "safe"),
        CleanRule("cocoapods-cache", "iOS / Mobile", "CocoaPods cache",
                  HOME / "Library/Caches/CocoaPods",
                  "Cache pod đã tải, tự tải lại khi `pod install`.", "safe"),
        CleanRule("homebrew-cache", "Khác", "Homebrew cache",
                  HOME / "Library/Caches/Homebrew",
                  "File cài đặt (.tar.gz/bottle) đã tải, brew tự tải lại khi cần.", "safe"),
        CleanRule("cargo-cache", "Khác", "Cargo registry cache",
                  HOME / ".cargo/registry/cache",
                  "Cache crate Rust đã tải, tự tải lại khi build.", "safe"),
        CleanRule("pip-cache", "Khác", "pip cache",
                  HOME / "Library/Caches/pip",
                  "Cache package Python đã tải, tự tải lại khi cần.", "safe"),
        CleanRule("go-build-cache", "Khác", "Go build cache",
                  HOME / "Library/Caches/go-build",
                  "Cache build Go, tự tạo lại khi build.", "safe"),
        CleanRule("playwright-cache", "Khác", "Playwright browsers",
                  HOME / "Library/Caches/ms-playwright",
                  "Browser binary Playwright đã tải, tự tải lại khi cần.", "safe"),
    ]


# Các thư mục con của ~/Library/Caches đã có rule riêng ở trên — bỏ qua khi quét động
_DYNAMIC_SKIP_NAMES = {"Yarn", "CocoaPods", "Homebrew", "pip", "go-build", "ms-playwright"}


def _dynamic_cache_items() -> List[Tuple[str, Path, str]]:
    """Quét động từng thư mục con trong ~/Library/Caches và ~/Library/Logs
    chưa có rule cố định — mỗi app/tool một mục riêng để xóa lẻ."""
    items: List[Tuple[str, Path, str]] = []
    caches_root = HOME / "Library/Caches"
    if caches_root.exists():
        try:
            for entry in caches_root.iterdir():
                if entry.name.startswith(".") or entry.name in _DYNAMIC_SKIP_NAMES:
                    continue
                items.append((
                    "Cache ứng dụng khác",
                    entry,
                    "Cache của ứng dụng, xóa an toàn — ứng dụng tự tạo lại khi cần.",
                ))
        except OSError:
            pass
    logs_root = HOME / "Library/Logs"
    if logs_root.exists():
        try:
            for entry in logs_root.iterdir():
                if entry.name.startswith("."):
                    continue
                items.append(("Logs", entry, "File log ứng dụng, xóa an toàn."))
        except OSError:
            pass
    return items


def get_cleaner_targets() -> List[Dict[str, object]]:
    """Toàn bộ mục CÓ THỂ dọn trên ổ Mac (chưa tính size)."""
    targets: List[Dict[str, object]] = []
    for rule in _cleaner_rules():
        targets.append({
            "id": rule.id,
            "category": rule.category,
            "label": rule.label,
            "path": rule.path,
            "description": rule.description,
            "risk": rule.risk,
        })
    for category, path, desc in _dynamic_cache_items():
        targets.append({
            "id": f"dyn:{path}",
            "category": category,
            "label": path.name,
            "path": path,
            "description": desc,
            "risk": "safe",
        })
    return targets


CLEANER_LOCK = threading.Lock()
CLEANER_STATUS = "idle"
CLEANER_PROGRESS = 0.0
CLEANER_CURRENT_ITEM = ""
CLEANER_ITEMS: List[Dict[str, object]] = []
CLEANER_TOTAL_SIZE = 0


def get_cleaner_status() -> Dict[str, object]:
    """Snapshot trạng thái quét hiện tại — đọc qua hàm (không import biến thô)
    để luôn thấy giá trị mới nhất do thread quét cập nhật."""
    with CLEANER_LOCK:
        return {
            "status": CLEANER_STATUS,
            "progress": CLEANER_PROGRESS,
            "current_item": CLEANER_CURRENT_ITEM,
            "items": list(CLEANER_ITEMS),
            "total_size": CLEANER_TOTAL_SIZE,
            "total_size_human": human_size(CLEANER_TOTAL_SIZE),
        }


def scan_cleaner_task() -> None:
    global CLEANER_STATUS, CLEANER_PROGRESS, CLEANER_CURRENT_ITEM, CLEANER_ITEMS, CLEANER_TOTAL_SIZE
    with CLEANER_LOCK:
        if CLEANER_STATUS == "scanning":
            return
        CLEANER_STATUS = "scanning"
        CLEANER_PROGRESS = 0.0
        CLEANER_CURRENT_ITEM = "Chuẩn bị quét..."
        CLEANER_ITEMS = []
        CLEANER_TOTAL_SIZE = 0

    try:
        targets = get_cleaner_targets()
        total = len(targets) or 1
        results: List[Dict[str, object]] = []
        for i, target in enumerate(targets):
            path = target["path"]
            with CLEANER_LOCK:
                CLEANER_CURRENT_ITEM = f"Quét: {target['label']}"
                CLEANER_PROGRESS = i / total
            if not (path.exists() or path.is_symlink()):
                continue
            size = du_size(path)
            if size <= 0:
                continue
            results.append({
                "id": target["id"],
                "category": target["category"],
                "label": target["label"],
                "path": str(path),
                "description": target["description"],
                "risk": target["risk"],
                "size": size,
                "size_human": human_size(size),
            })

        if TRASH_DIR.exists():
            trash_size = du_size(TRASH_DIR)
            if trash_size > 0:
                results.append({
                    "id": "trash",
                    "category": "Thùng rác",
                    "label": "Thùng rác (Trash)",
                    "path": str(TRASH_DIR),
                    "description": "File đã xóa còn nằm trong Trash. Đổ rác không thể hoàn tác.",
                    "risk": "caution",
                    "size": trash_size,
                    "size_human": human_size(trash_size),
                })

        results.sort(key=lambda r: r["size"], reverse=True)
        with CLEANER_LOCK:
            CLEANER_ITEMS = results
            CLEANER_TOTAL_SIZE = sum(r["size"] for r in results)
            CLEANER_STATUS = "done"
            CLEANER_PROGRESS = 1.0
            CLEANER_CURRENT_ITEM = "Quét hoàn tất."
    except Exception as exc:
        with CLEANER_LOCK:
            CLEANER_STATUS = "error"
            CLEANER_CURRENT_ITEM = f"Lỗi quét: {exc}"


def start_background_cleaner_scan() -> None:
    threading.Thread(target=scan_cleaner_task, daemon=True).start()


def clean_selected_paths(paths_to_delete: List[str], log: JobLog) -> None:
    """Xóa các mục đã chọn. Chỉ chấp nhận đường dẫn đã từng xuất hiện trong lần
    quét gần nhất (CLEANER_ITEMS) và nằm trong $HOME — chống xóa nhầm đường dẫn
    tùy ý được gửi lên từ client."""
    with CLEANER_LOCK:
        allowed = {item["path"]: item for item in CLEANER_ITEMS}

    home_resolved = str(HOME.resolve())
    freed = 0
    ok_count = 0
    fail_count = 0

    for path_str in paths_to_delete:
        item = allowed.get(path_str)
        if not item:
            log.info(f"Bo qua (khong nam trong lan quet gan nhat): {path_str}")
            fail_count += 1
            continue

        path = Path(path_str)
        try:
            resolved = str(path.resolve()) if (path.exists() or path.is_symlink()) else str(path)
        except OSError:
            resolved = str(path)
        if not resolved.startswith(home_resolved):
            log.info(f"Bo qua (nam ngoai pham vi cho phep): {path_str}")
            fail_count += 1
            continue

        log.info(f"Dang xoa: {item['label']} ({item['size_human']}) - {path_str}")
        try:
            if path == TRASH_DIR:
                for child in path.iterdir():
                    remove_path(child)
            elif path.is_symlink():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(str(path))
            elif path.exists():
                path.unlink()
            freed += item["size"]
            ok_count += 1
        except Exception as exc:
            log.info(f"Loi khi xoa {path_str}: {exc}")
            fail_count += 1

    log.done(f"Xong. Da xoa {ok_count} muc, loi {fail_count} muc, giai phong khoang {human_size(freed)}.")


def delete_unavailable_simulators(log: JobLog) -> None:
    """`xcrun simctl delete unavailable` — chỉ xóa các iOS Simulator không còn
    dùng được (không đụng tới simulator đang hoạt động)."""
    log.info("Dang xoa cac iOS Simulator khong con dung duoc...")
    try:
        result = subprocess.run(
            ["xcrun", "simctl", "delete", "unavailable"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Khong the chay xcrun simctl: {exc}")
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "xcrun simctl delete unavailable that bai.").strip())
    log.done("Da xoa cac iOS Simulator khong con dung duoc.")
