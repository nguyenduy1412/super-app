'''
AdFree Patcher — pipeline xóa quảng cáo khỏi APK (tự host, không cần root).

Luồng: apktool decode → quét & vô hiệu hóa SDK quảng cáo (smali + AndroidManifest)
→ apktool build → zipalign → apksigner ký.

Cách dùng CLI:
    python3 patcher.py input.apk [output.apk] [--no-reward] [--no-offline]
'''
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import assetinfo
import bundle
import offlinepatch
import rewardpatch

ROOT = Path(__file__).resolve().parent
SIG_FILE = ROOT / 'ad_signatures.json'
APKTOOL = Path(os.environ.get('APKTOOL', ROOT.parent / 'apktool.jar'))
KEYSTORE = Path(os.environ.get('ADFREE_KEYSTORE', ROOT / 'keystore.jks'))
KEY_ALIAS = os.environ.get('ADFREE_KEY_ALIAS', 'adfree')
KEY_PASS = os.environ.get('ADFREE_KEY_PASS', 'adfree-key')

MANIFEST = 'AndroidManifest.xml'


def run(cmd, log=None):
    '''Chạy lệnh ngoài, trả (rc, output).'''
    proc = subprocess.run([str(c) for c in cmd],
                          capture_output=True, text=True, errors='replace')
    out = (proc.stdout or '') + (proc.stderr or '')
    if log is not None:
        log.append(out[-4000:])
    return proc.returncode, out


def find_build_tools():
    '''Tìm thư mục build-tools của Android SDK có apksigner + zipalign.'''
    env = os.environ.get('ANDROID_BUILD_TOOLS')
    cands = [Path(env)] if env else []
    sdk = Path(os.environ.get('ANDROID_HOME',
                              Path.home() / 'Library' / 'Android' / 'sdk'))
    bt = sdk / 'build-tools'
    if bt.is_dir():
        def ver(p):
            try:
                return [int(x) for x in re.findall(r'\d+', p.name)] or [0]
            except Exception:
                return [0]
        cands += sorted((p for p in bt.iterdir() if p.is_dir()),
                        key=ver, reverse=True)
    for c in cands:
        if (c / 'apksigner').exists() and (c / 'zipalign').exists():
            return c
    return None

DOCKER_IMAGE = os.environ.get("ADFREE_DOCKER_IMAGE", "adfree-tools:1")
DOCKERFILE = ROOT / "Dockerfile.tools"


def docker_cli():
    """Đường dẫn docker nếu CLI có VÀ daemon đang chạy, ngược lại None."""
    exe = shutil.which("docker")
    if not exe:
        return None
    rc, _ = run([exe, "info", "--format", "{{.ServerVersion}}"])
    return exe if rc == 0 else None


def docker_image_ready(exe):
    rc, _ = run([exe, "image", "inspect", DOCKER_IMAGE])
    return rc == 0


def build_docker_image(exe, log=None):
    """Dựng ảnh chứa JDK + apktool. Chỉ chạy một lần, cần mạng."""
    if not DOCKERFILE.exists():
        return False, f"Thiếu {DOCKERFILE}"
    rc, out = run([exe, "build", "-t", DOCKER_IMAGE, "-f", str(DOCKERFILE),
                   str(DOCKERFILE.parent)], log)
    return rc == 0, out[-2000:]


class JavaTools:
    """Chạy công cụ Java (apktool, keytool, jarsigner).

    Ưu tiên bản cài sẵn trên máy. Nếu máy thiếu Java hoặc apktool mà có Docker
    đang chạy thì tự chuyển sang chạy trong container — người dùng không phải
    cài JDK. Đường dẫn trên máy được ánh xạ vào container qua các volume khai
    báo trong `mounts`.
    """

    def __init__(self, log=None):
        self.log = log
        self.docker = None
        self.mode = None
        if shutil.which("java") and APKTOOL.exists():
            self.mode = "native"
            return
        exe = docker_cli()
        if exe:
            self.docker = exe
            self.mode = "docker"

    def ensure_ready(self):
        """Chuẩn bị chế độ đang chọn; trả về (sẵn sàng, lý do nếu chưa)."""
        if self.mode == "native":
            return True, ""
        if self.mode != "docker":
            return False, "Máy không có Java/apktool, cũng không có Docker đang chạy"
        if docker_image_ready(self.docker):
            return True, ""
        if self.log is not None:
            self.log.append(f"[docker] chưa có ảnh {DOCKER_IMAGE}, đang dựng…")
        ok, out = build_docker_image(self.docker, self.log)
        return (True, "") if ok else (False, f"Dựng ảnh Docker thất bại: {out}")

    def _map(self, argv, mounts):
        """Đổi đường dẫn trên máy sang đường dẫn trong container."""
        pairs = []
        for index, host in enumerate(mounts):
            host = Path(host).resolve()
            pairs.append((host, f"/mnt{index}"))
        mapped = []
        for item in argv:
            text = str(item)
            for host, inside in pairs:
                try:
                    relative = Path(text).resolve().relative_to(host)
                except (ValueError, OSError):
                    continue
                text = inside if str(relative) == "." else f"{inside}/{relative}"
                break
            mapped.append(text)
        volumes = []
        for host, inside in pairs:
            volumes += ["-v", f"{host}:{inside}"]
        return mapped, volumes

    def run(self, argv, mounts=()):
        """Chạy một lệnh Java. `mounts` là các thư mục lệnh cần đọc/ghi."""
        if self.mode == "native":
            return run(argv, self.log)
        if self.mode != "docker":
            return 1, "Không có Java trên máy và cũng không có Docker."
        # trong ảnh, apktool nằm sẵn ở /opt/apktool.jar
        argv = [("/opt/apktool.jar" if str(a) == str(APKTOOL) else a)
                for a in argv]
        mapped, volumes = self._map(argv, mounts)
        command = [self.docker, "run", "--rm"] + volumes + [DOCKER_IMAGE] + mapped
        return run(command, self.log)


def tool_status():
    """Công cụ ngoài nào đang có, và thiếu cái gì thì mất tính năng gì.

    Chế độ chỉ-phân-tích không cần gì ngoài Python. Chế độ chặn quảng cáo cần
    apktool (chạy trên Java) để tháo/ráp APK — phần này không thay bằng Python
    được vì phải dịch qua lại dex ↔ smali và mã hoá lại AndroidManifest/resources.
    """
    java = shutil.which("java")
    apktool = APKTOOL.exists()
    build_tools = find_build_tools()
    jarsigner = shutil.which("jarsigner")
    keytool = shutil.which("keytool")
    docker = docker_cli()
    native_ok = bool(java and apktool)
    warnings = []
    blockers = []
    if not native_ok and not docker:
        if not java:
            blockers.append("Thiếu Java — cài JRE/JDK 11 trở lên, hoặc bật "
                            "Docker để chạy tự động trong container")
        if not apktool:
            blockers.append(f"Thiếu apktool.jar — đặt tại {APKTOOL}, đặt biến "
                            "môi trường APKTOOL, hoặc bật Docker")
    if native_ok and not (build_tools or jarsigner):
        blockers.append("Không có cách ký APK — cần Android build-tools "
                        "(apksigner) hoặc jarsigner trong JDK")
    if not build_tools and (jarsigner or docker):
        warnings.append("Không có build-tools nên chỉ ký được v1 (jarsigner); "
                        "APK có thể không cài được trên Android 11+")
    if java and not keytool:
        warnings.append("Không có keytool — không tự tạo được keystore mới")
    if not native_ok and docker:
        warnings.append("Máy thiếu Java/apktool — sẽ tự chạy qua Docker "
                        f"(ảnh {DOCKER_IMAGE}, lần đầu cần mạng để dựng)")
    return {
        "analyze_ready": True,          # chỉ cần thư viện chuẩn Python
        "patch_ready": not blockers,
        "mode": "native" if native_ok else ("docker" if docker else None),
        "docker": docker,
        "java": java, "apktool": str(APKTOOL) if apktool else None,
        "build_tools": str(build_tools) if build_tools else None,
        "jarsigner": jarsigner, "keytool": keytool,
        "blockers": blockers, "warnings": warnings,
    }


def ensure_keystore(tools=None):
    '''Tạo keystore ký APK nếu chưa có.'''
    if KEYSTORE.exists():
        return
    KEYSTORE.parent.mkdir(parents=True, exist_ok=True)
    runner = tools.run if tools else run
    (rc, out) = runner([
        'keytool', '-genkeypair',
        '-keystore', KEYSTORE, '-alias', KEY_ALIAS,
        '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
        '-storepass', KEY_PASS, '-keypass', KEY_PASS,
        '-dname', 'CN=AdFree Patcher, OU=Local, O=AdFree, L=Local, C=VN'])
    if rc != 0:
        raise RuntimeError(f'Không tạo được keystore: {out[-500:]}')


METHOD_RE = re.compile(
    r'^\.method\s+((?:public|private|protected|static|final|synchronized|'
    r'varargs|bridge|native|abstract|constructor|declared-synchronized|\s)+)'
    r'(\S+)\(([^)]*)\)(\S+)', re.M)

RET_CODES = {
    'V': (0, '    return-void'),
    'Z': (1, '    const/4 v0, 0x1\n    return v0'),
    'B': (1, '    const/4 v0, 0x0\n    return v0'),
    'S': (1, '    const/4 v0, 0x0\n    return v0'),
    'C': (1, '    const/4 v0, 0x0\n    return v0'),
    'I': (1, '    const/4 v0, 0x0\n    return v0'),
    'F': (1, '    const/4 v0, 0x0\n    return v0'),
    'J': (2, '    const-wide/16 v0, 0x0\n    return-wide v0'),
    'D': (2, '    const-wide/16 v0, 0x0\n    return-wide v0'),
}


def sign_apk(src, dst, workdir, log=None, tools=None):
    '''zipalign + ký một APK bằng khoá AdFree. Trả về mô tả loại chữ ký.'''
    runner = tools.run if tools else run
    ensure_keystore(tools)
    bt = find_build_tools()
    aligned = Path(workdir) / (Path(src).stem + '.aligned.apk')
    if bt:
        runner([bt / 'zipalign', '-f', '-p', '4', src, aligned], log)
        (rc, _) = runner([
            bt / 'apksigner', 'sign',
            '--ks', KEYSTORE, '--ks-key-alias', KEY_ALIAS,
            '--ks-pass', f'pass:{KEY_PASS}',
            '--key-pass', f'pass:{KEY_PASS}',
            '--out', dst, aligned], log)
        aligned.unlink(missing_ok=True)
        if rc != 0:
            raise RuntimeError(f'apksigner ký thất bại: {Path(src).name}')
        return 'v2/v3 (apksigner)'
    (rc, _) = runner([
        'jarsigner', '-keystore', KEYSTORE,
        '-storepass', KEY_PASS, '-keypass', KEY_PASS,
        '-signedjar', str(dst), str(src), KEY_ALIAS], log)
    if rc != 0:
        raise RuntimeError(f'jarsigner ký thất bại: {Path(src).name}')
    return 'v1 (jarsigner)'


def return_stmt(ret):
    '''Lệnh smali trả về giá trị mặc định cho descriptor kiểu trả về.'''
    return RET_CODES.get(ret, (1, '    const/4 v0, 0x0\n    return-object v0'))


def count_param_regs(params):
    '''Đếm số thanh ghi chiếm bởi danh sách tham số smali descriptor.'''
    total = 0
    i = 0
    while i < len(params):
        ch = params[i]
        if ch in 'JD':
            total += 2
            i += 1
        elif ch == 'L':
            total += 1
            i = params.index(';', i) + 1
        elif ch == '[':
            j = i
            while j < len(params) and params[j] == '[':
                j += 1
            if j < len(params) and params[j] == 'L':
                total += 1
                i = params.index(';', j) + 1
            else:
                total += 1
                i = j + 1
        else:
            total += 1
            i += 1
    return total


def patch_smali_methods(text, method_names):
    '''Thay thân các method khớp tên bằng lệnh return sớm. Trả (text mới, số method đã patch).'''
    patched = 0
    out = []
    cursor = 0
    for m in METHOD_RE.finditer(text):
        decl = m.group(0)
        flags = m.group(1)
        name = m.group(2)
        params = m.group(3)
        ret = m.group(4)
        if name in ('<init>', '<clinit>'):
            continue
        if method_names and name not in method_names:
            continue
        if 'native' in flags or 'abstract' in flags:
            continue
        end = text.find('.end method', m.end())
        if end == -1:
            continue
        body = text[m.end():end]
        dir_m = re.search(r'^\s*\.(locals|registers)\s+(\d+)', body, re.M)
        if dir_m:
            kind = dir_m.group(1)
            n = int(dir_m.group(2))
            available = n if kind == 'registers' else n + count_param_regs(params)
            keep = f'    .{kind} {n}'
        else:
            available = count_param_regs(params)
            keep = None
        if ret != 'V' and available == 0:
            keep = '    .locals 1'
        stmt = return_stmt(ret)[1]
        out.append(text[cursor:m.start()])
        out.append(decl + '\n' + ((keep + '\n') if keep else '') + stmt + '\n.end method\n')
        patched += 1
        cursor = end + len('.end method')
    out.append(text[cursor:])
    return ''.join(out), patched


def patch_smali_file(path, entries):
    '''Áp các patch (tên method) cho một file smali. Trả số method đã patch.'''
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return 0
    new, n = patch_smali_methods(text, entries)
    if n:
        path.write_text(new, encoding='utf-8')
    return n


def find_smali_dirs(decoded):
    '''Các thư mục smali* trong APK đã decode.'''
    return sorted(p for p in Path(decoded).iterdir()
                  if p.is_dir() and p.name.startswith('smali'))


def load_signatures():
    if not SIG_FILE.exists():
        return {'sdks': [], 'manifest_permissions': []}
    return json.loads(SIG_FILE.read_text(encoding='utf-8'))


def scan_sdks(decoded, sigs):
    '''
    Quét cây smali theo packages của từng SDK.
    Trả detection: {'sdks': [{name, packages, files}], 'total_files': N}
    '''
    dirs = find_smali_dirs(decoded)
    found = []
    total = 0
    for sdk in sigs.get('sdks', []):
        files = 0
        for pkg in sdk.get('packages', []):
            rel = Path(pkg)
            for d in dirs:
                base = d / rel
                if base.is_dir():
                    files += sum(1 for _ in base.rglob('*.smali'))
        if files:
            found.append({'name': sdk['name'],
                          'packages': sdk.get('packages', []),
                          'files': files})
            total += files
    return {'sdks': found, 'total_files': total}


def clean_manifest(decoded, sigs, detection, log):
    '''Xóa Activity/Service/Receiver của SDK + quyền quảng cáo khỏi manifest.'''
    mf = Path(decoded) / MANIFEST
    if not mf.exists():
        return {'components_removed': 0, 'permissions_removed': 0}
    text = mf.read_text(encoding='utf-8', errors='replace')
    comp_removed = 0
    perm_removed = 0
    # Components của SDK đã phát hiện
    names = set()
    for sdk in sigs.get('sdks', []):
        pkg_prefixes = tuple(p.replace('/', '.') for p in sdk.get('packages', []))
        known = sdk.get('components', [])
        for c in known:
            if any(c.startswith(pp) for pp in pkg_prefixes) or \
               any(s['name'] == sdk['name'] for s in detection.get('sdks', [])):
                names.add(c)
    for comp in names:
        # <activity android:name="com.foo.Bar" .../> hoặc <activity android:name=".Bar">
        pat = re.compile(
            r'<(activity|service|receiver|provider)\b[^>]*android:name="%s"[^>]*/?>\s*'
            % re.escape(comp))
        text2, n = pat.subn('', text)
        if n:
            text = text2
            comp_removed += n
    # Quyền quảng cáo
    for perm in sigs.get('manifest_permissions', []):
        pat = re.compile(r'<uses-permission\b[^>]*android:name="%s"[^>]*/>\s*'
                         % re.escape(perm))
        text2, n = pat.subn('', text)
        if n:
            text = text2
            perm_removed += n
    mf.write_text(text, encoding='utf-8')
    log.append(f'[manifest] Xóa {comp_removed} component, {perm_removed} quyền.')
    return {'components_removed': comp_removed,
            'permissions_removed': perm_removed}


class Patcher:
    '''Pipeline vá một APK: decode → patch smali/manifest → build → sign.'''

    def __init__(self, workdir=None, fake_reward=True, offline=True,
                 analyze_assets=False, block_ads=True):
        self.no_reward = not fake_reward
        self.no_offline = not offline
        self.workdir = Path(workdir) if workdir else None
        self.analyze_assets = analyze_assets
        self.log = []
        self.progress = None   # callback(step, label, pct) do server gán vào
        # chọn cách chạy công cụ Java: sẵn trên máy, hoặc lùi về Docker
        self.tools = JavaTools(self.log)

    def _progress(self, step, label, pct):
        if callable(self.progress):
            try:
                self.progress(step, label, pct)
            except Exception:
                pass

    def patch(self, input_apk, output_apk):
        '''
        Vá input_apk → output_apk. Trả về report dict cho UI/API.
        Ném RuntimeError nếu decode/build thất bại.
        '''
        input_apk = Path(input_apk).resolve()
        output_apk = Path(output_apk).resolve()
        work = self.workdir or (output_apk.parent / ('.adfree-' + output_apk.stem))
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        log = self.log
        self._progress('decode', 'Đang giải nén APK bằng apktool…', 5)
        report = {
            'input': input_apk.name,
            'output': output_apk.name,
            'started': datetime.now().isoformat(timespec='seconds'),
            'log': log,
        }

        # 1) Decode
        decoded = work / 'decoded'
        status = tool_status()
        if not status['patch_ready']:
            report['error'] = 'Máy này chưa đủ công cụ để chặn quảng cáo'
            report['detail'] = '\n  · '.join(status['blockers']) + \
                '\n(Chế độ chỉ phân tích tài nguyên vẫn chạy được bình thường.)'
            return report
        ready, why = self.tools.ensure_ready()
        if not ready:
            report['error'] = why
            return report
        log.append('[tools] dùng Java cài sẵn trên máy'
                   if self.tools.mode == 'native'
                   else f'[tools] máy thiếu Java/apktool — chạy qua Docker ({DOCKER_IMAGE})')
        mounts = (work, input_apk.parent, KEYSTORE.parent)
        rc, out = self.tools.run(['java', '-jar', APKTOOL, 'd', '-f', '-o',
                                  decoded, input_apk], mounts)
        if rc != 0:
            report['error'] = 'apktool decode thất bại'
            report['detail'] = out[-1500:]
            return report
        log.append('[decode] OK')

        # 2) Quét SDK
        sigs = load_signatures()
        detection = scan_sdks(decoded, sigs)
        report['detection'] = detection
        log.append(f"[scan] Phát hiện {len(detection['sdks'])} SDK, "
                   f"{detection['total_files']} file smali.")

        # 3) Vô hiệu hóa method SDK
        neutralized = 0
        for sdk in detection['sdks']:
            names = set()
            for s in sigs['sdks']:
                if s['name'] == sdk['name']:
                    names.update(s.get('neutralize', []))
            for smali in _sdk_smali_files(decoded, sdk):
                neutralized += patch_smali_file(smali, names)
        report['neutralized'] = neutralized
        self._progress('patch', 'Đã vô hiệu hoá SDK quảng cáo', 40)
        log.append(f'[patch] Vô hiệu hóa {neutralized} method.')

        # 4) Manifest
        report['manifest'] = clean_manifest(decoded, sigs, detection, log)

        # 5) Offline patch
        smali_dirs = find_smali_dirs(decoded)
        report['offline'] = (offlinepatch.apply(decoded, detection,
                                                smali_dirs, log)
                             if not self.no_offline else
                             {'enabled': False, 'files': 0, 'rewrites': 0})

        # 6) Reward patch
        report['reward'] = (rewardpatch.apply(decoded, detection,
                                              smali_dirs, log)
                            if not self.no_reward else
                            {'enabled': False, 'methods_patched': 0})
        self._progress('build', 'Đóng gói lại APK…', 75)

        # 7) Build + sign
        unsigned = work / 'unsigned.apk'
        rc, out = self.tools.run(['java', '-jar', APKTOOL, 'b', decoded,
                                  '-o', unsigned], mounts)
        self._progress('sign', 'Căn lề và ký APK…', 90)
        if rc != 0:
            report['error'] = 'apktool build thất bại'
            report['detail'] = out[-1500:]
            return report
        report['signature'] = sign_apk(unsigned, output_apk, work, log,
                                       tools=self.tools)
        report['finished'] = datetime.now().isoformat(timespec='seconds')
        report['ok'] = True
        return report


def _sdk_smali_files(decoded, sdk):
    '''Sinh các file smali thuộc SDK.'''
    for d in find_smali_dirs(decoded):
        for pkg in sdk.get('packages', []):
            base = d / pkg
            if base.is_dir():
                yield from base.rglob('*.smali')


def patch_bundle(source, out_dir, workdir=None, fake_reward=True,
                 on_progress=None, offline=True, analyze_assets=False):
    '''
    Vá một bộ split APK (thư mục hoặc .xapk/.apks): vá base, ký lại mọi file,
    đóng gói kèm install.sh. Trả về report.
    '''
    out_dir = Path(out_dir).resolve()
    work = Path(workdir) if workdir else \
        (out_dir.parent / ('.adfree-bundle-' + out_dir.stem))
    apks = bundle.collect_apks(source, work)
    if not apks:
        raise RuntimeError('Không tìm thấy APK nào trong nguồn.')
    base = bundle.pick_base(apks)
    splits = [a for a in apks if a != base]
    p = Patcher(workdir=work / 'patch-base', fake_reward=fake_reward,
                offline=offline, analyze_assets=analyze_assets)
    if callable(on_progress):
        p.progress = on_progress
    patched_base = work / ('patched-' + base.name)
    report = p.patch(base, patched_base)
    if not report.get('ok'):
        return report
    # Ký lại toàn bộ split bằng cùng khoá
    signed_splits = []
    for s in splits:
        dst = work / s.name
        sign_apk(s, dst, work)
        signed_splits.append(dst)
    # Split KHÔNG được vá smali nhưng phải chung chữ ký → giữ nguyên file, chỉ ký
    final = bundle.package_bundle(
        out_dir, patched_base, signed_splits,
        signature_note=f"Chữ ký: {report.get('signature')} — AdFree Patcher")
    # Đóng cả thư mục kết quả thành 1 file .apks để UI tải về 1 lần
    zip_path = out_dir.parent / (out_dir.stem + '.apks')
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(Path(final).rglob('*')):
            if f.is_file():
                zf.write(f, f.relative_to(final))
    report['bundle'] = {'dir': str(final), 'zip': str(zip_path)}
    report['splits_signed'] = len(signed_splits)
    return report


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    no_reward = '--no-reward' in argv
    no_offline = '--no-offline' in argv
    argv = [a for a in argv if not a.startswith('--')]
    if not argv:
        print(__doc__)
        return 2
    src = Path(argv[0])
    dst = Path(argv[1]) if len(argv) > 1 else \
        src.with_name(src.stem + '-adfree' + src.suffix)
    p = Patcher(no_reward=no_reward, no_offline=no_offline)
    report = p.patch(src, dst)
    if report.get('ok'):
        print(f"OK: {dst}")
        print(f"  SDK: {[s['name'] for s in report['detection']['sdks']]}")
        print(f"  Method vô hiệu hóa: {report['neutralized']}")
        print(f"  Reward patched: {report['reward'].get('methods_patched', 0)}")
        print(f"  Chữ ký: {report['signature']}")
        return 0
    print('THẤT BẠI:', report.get('error'))
    print(report.get('detail', ''))
    return 1


if __name__ == '__main__':
    sys.exit(main())
