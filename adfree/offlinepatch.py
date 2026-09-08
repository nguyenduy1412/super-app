'''
Ép SDK quảng cáo "nghĩ rằng" thiết bị offline (chiến lược Offline patch của Lucky Patcher).

Ad SDK kiểm tra mạng trước khi tải quảng cáo. Module này:
  1. Tiêm class hook Ladfree/hook/OfflineHook; — mọi method đều trả
     "không có mạng" (null / false).
  2. Đổi mọi lệnh invoke gọi API kiểm tra mạng của Android (ConnectivityManager,
     NetworkInfo) trong code SDK quảng cáo thành invoke-static gọi hook —
     SDK nhìn đâu cũng thấy offline nên bỏ qua tải ads, còn app thì vẫn
     dùng mạng bình thường vì chỉ code SDK bị đổi.

Chỉ áp cho file smali của SDK đã được phát hiện, không đụng code của app.
'''
import re
from pathlib import Path

STUB_DESC = 'Ladfree/hook/OfflineHook;'
STUB_CODE = '''
.class public Ladfree/hook/OfflineHook;
.super Ljava/lang/Object;

.method public static getActiveNetworkInfo(Landroid/net/ConnectivityManager;)Landroid/net/NetworkInfo;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public static getActiveNetwork(Landroid/net/ConnectivityManager;)Landroid/net/Network;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public static getNetworkCapabilities(Landroid/net/ConnectivityManager;Landroid/net/Network;)Landroid/net/NetworkCapabilities;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public static isConnected(Landroid/net/NetworkInfo;)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public static isConnectedOrConnecting(Landroid/net/NetworkInfo;)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public static isAvailable(Landroid/net/NetworkInfo;)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
'''
RULES = [
    ('Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;',
     'getActiveNetworkInfo', '(Landroid/net/ConnectivityManager;)Landroid/net/NetworkInfo;'),
    ('Landroid/net/ConnectivityManager;->getActiveNetwork()Landroid/net/Network;',
     'getActiveNetwork', '(Landroid/net/ConnectivityManager;)Landroid/net/Network;'),
    ('Landroid/net/ConnectivityManager;->getNetworkCapabilities(Landroid/net/Network;)Landroid/net/NetworkCapabilities;',
     'getNetworkCapabilities', '(Landroid/net/ConnectivityManager;Landroid/net/Network;)Landroid/net/NetworkCapabilities;'),
    ('Landroid/net/NetworkInfo;->isConnected()Z',
     'isConnected', '(Landroid/net/NetworkInfo;)Z'),
    ('Landroid/net/NetworkInfo;->isConnectedOrConnecting()Z',
     'isConnectedOrConnecting', '(Landroid/net/NetworkInfo;)Z'),
    ('Landroid/net/NetworkInfo;->isAvailable()Z',
     'isAvailable', '(Landroid/net/NetworkInfo;)Z'),
]


def _compile_rules():
    out = []
    for ref, name, desc in RULES:
        pat = re.compile(
            r'invoke-virtual(/range)?(\s*\{[^}]*\})\s*,\s*' + re.escape(ref))
        repl = f'invoke-static\\1\\2, {STUB_DESC}->{name}{desc}'
        out.append((pat, repl, name))
    return out


def apply(decoded, detection, smali_dirs, log):
    '''Chuyển hướng lệnh kiểm tra mạng trong code SDK sang hook offline.'''
    decoded = Path(decoded)
    if not detection:
        log.append('[offline] Bỏ qua — không phát hiện SDK quảng cáo nào.')
        return {'enabled': False, 'files': 0, 'rewrites': 0}

    smali_dirs = [Path(d) for d in smali_dirs if Path(d).is_dir()]
    if not smali_dirs:
        log.append('[offline] Bỏ qua — không có thư mục smali.')
        return {'enabled': False, 'files': 0, 'rewrites': 0}

    # 1) Tiêm class hook vào thư mục smali đầu tiên
    stub_path = smali_dirs[0] / 'adfree/hook/OfflineHook.smali'
    stub_path.parent.mkdir(parents=True, exist_ok=True)
    stub_path.write_text(STUB_CODE.lstrip('\n'), encoding='utf-8')
    log.append(f'[offline] Tiêm hook: {stub_path.relative_to(decoded)}')

    # 2) Xác định thư mục smali của SDK đã phát hiện
    pkg_dirs = []
    for sdk in detection.get('sdks', []):
        for pkg in sdk.get('packages', []):
            rel = Path(pkg)
            for sd in smali_dirs:
                d = sd / rel
                if d.is_dir():
                    pkg_dirs.append(d)
                    break
    if not pkg_dirs:
        log.append('[offline] Bỏ qua — không tìm thấy thư mục smali của SDK.')
        return {'enabled': True, 'files': 0, 'rewrites': 0}

    rules = _compile_rules()
    files_changed = 0
    rewrites = 0
    for d in pkg_dirs:
        for smali in d.rglob('*.smali'):
            try:
                text = smali.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            new = text
            hit = False
            for pat, repl, _name in rules:
                new2, n = pat.subn(repl, new)
                if n:
                    new = new2
                    rewrites += n
                    hit = True
            if hit:
                smali.write_text(new, encoding='utf-8')
                files_changed += 1
    log.append(f'[offline] Đổi {rewrites} lệnh kiểm tra mạng trong {files_changed} file smali.')
    return {'enabled': True, 'files': files_changed, 'rewrites': rewrites}
