'''
Build lại APK từ thư mục đã decode + ký, KHÔNG decode lại (giữ mọi sửa đổi smali).

Dùng:
    python3 rebuild_signed.py <thu_muc_decoded> <apk_ra>
'''
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import patcher


def main():
    decoded = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2]).resolve()
    work = out.parent / ('.build-' + out.stem)
    work.mkdir(parents=True, exist_ok=True)
    log = []
    unsigned = work / 'unsigned.apk'
    (rc, o) = patcher.run([
        'java', '-jar', patcher.APKTOOL,
        'b', decoded, '-o', unsigned], log)
    if rc != 0:
        print('BUILD FAIL:\n', o[-1500:])
        sys.exit(1)
    sig = patcher.sign_apk(unsigned, out, work, log)
    print('OK:', out, '|', sig)


if __name__ == '__main__':
    main()
