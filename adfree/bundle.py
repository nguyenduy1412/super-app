'''
Xử lý app dạng split APK (Android App Bundle).

App cài từ Google Play thường gồm base.apk + nhiều split_*.apk. Android bắt buộc
cài cả bộ cùng lúc và **mọi file phải cùng một chữ ký** — cài mỗi base.apk đã vá
sẽ báo INSTALL_FAILED_MISSING_SPLIT, còn trộn bản vá với split gốc sẽ báo lỗi
chữ ký không khớp.

Module này: vá base.apk → ký lại toàn bộ split bằng cùng một khoá → đóng gói
kèm script cài đặt.
'''
import shutil
import zipfile
from pathlib import Path

APK_MAGIC = b'PK\x03\x04'


def is_apk(path):
    '''File có phải APK không (zip chứa AndroidManifest.xml).'''
    path = Path(path)
    if not path.is_file():
        return False
    try:
        with path.open('rb') as f:
            if f.read(4) != APK_MAGIC:
                return False
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        return any(n == 'AndroidManifest.xml' for n in names)
    except Exception:
        return False


def collect_apks(source, workdir):
    '''
    Lấy danh sách APK từ nguồn đầu vào.

    source có thể là: thư mục chứa các .apk, hoặc file gộp (.xapk/.apks/.apkm/.zip).
    Trả về danh sách Path đã nằm sẵn trên đĩa.
    '''
    source = Path(source)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        return sorted(p for p in source.glob('*.apk') if is_apk(p))
    # File gộp: xép ra thư mục làm việc
    out = []
    try:
        with zipfile.ZipFile(source) as z:
            for info in z.infolist():
                name = Path(info.filename).name
                if name.endswith('.apk') and not name.startswith('.'):
                    dest = workdir / name
                    dest.write_bytes(z.read(info))
                    if is_apk(dest):
                        out.append(dest)
    except zipfile.BadZipFile:
        return [source] if is_apk(source) else []
    return sorted(out)


def pick_base(apks):
    '''Chọn base.apk (file có 'base' trong tên, hoặc APK đầu tiên).'''
    for a in apks:
        if 'base' in a.name.lower():
            return a
    return apks[0] if apks else None


def package_bundle(out_dir, patched_base, splits, signature_note=''):
    '''
    Đóng gói kết quả: base đã vá + các split đã ký lại + install script.
    Trả về thư mục Output.
    '''
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    shutil.copy2(patched_base, out_dir / patched_base.name)
    names = [patched_base.name]
    for s in splits:
        shutil.copy2(s, out_dir / s.name)
        names.append(s.name)
    script = [
        '#!/bin/bash',
        '# Cài app đã xoá quảng cáo (bộ split APK — phải cài tất cả cùng lúc).',
        '# Cần bật USB debugging trên điện thoại và cài adb trên máy tính.',
        'set -e',
        'DIR="$(cd "$(dirname "$0")" && pwd)"',
        'PKG=$(pm path 2>/dev/null || true)',
        "adb uninstall $(aapt dump badging \"$DIR/%s\" 2>/dev/null | sed -n \"s/package: name='\\([^']*\\)'.*/\\1/p\") 2>/dev/null || true" % patched_base.name,
        'echo "Đang cài %d file…"' % len(names),
        'adb install-multiple -r \\',
    ]
    script += ['    "$DIR/%s" \\' % n for n in names[:-1]]
    script += ['    "$DIR/%s"' % names[-1], '', 'echo "Xong!"', '']
    (out_dir / 'install.sh').write_text('\n'.join(script), encoding='utf-8')
    (out_dir / 'install.sh').chmod(0o755)
    if signature_note:
        (out_dir / 'SIGNED.txt').write_text(signature_note + '\n', encoding='utf-8')
    return out_dir
