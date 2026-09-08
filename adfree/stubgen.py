'''
Sinh class "giả" (stub) từ interface/abstract class có sẵn trong APK.

Dùng để tạo đối tượng hợp lệ truyền vào callback quảng cáo — ví dụ RewardItem,
MaxAd, MaxReward — nhờ đó có thể gọi thẳng callback "đã xem xong quảng cáo"
mà không crash (kể cả code Kotlin có kiểm tra non-null).
'''
import re
from pathlib import Path

CLASS_RE = re.compile(r'^\.class\s+(.*?)(L[^;]+;)\s*$', re.M)
SUPER_RE = re.compile(r'^\.super\s+(L[^;]+;)\s*$', re.M)
IFACE_RE = re.compile(r'^\.implements\s+(L[^;]+;)\s*$', re.M)
METHOD_RE = re.compile(r'^\.method\s+([^\n]*?)\s+([^\s(]+)\(([^)]*)\)(\S+)\s*$', re.M)
STR_DESC = 'Ljava/lang/String;'


def find_class_file(class_desc, smali_dirs):
    """Tìm file .smali của một class theo descriptor 'Lcom/foo/Bar;'."""
    rel = class_desc[1:-1] + '.smali'
    for sd in smali_dirs:
        p = Path(sd) / rel
        if p.is_file():
            return p
    return None


def parse_class(path):
    '''Đọc 1 file smali, trả về thông tin class.'''
    text = path.read_text(encoding='utf-8', errors='replace')
    cm = CLASS_RE.search(text)
    sm = SUPER_RE.search(text)
    return {
        'desc': cm.group(2) if cm else None,
        'flags': cm.group(1) if cm else '',
        'super': sm.group(1) if sm else 'Ljava/lang/Object;',
        'interfaces': IFACE_RE.findall(text),
        'methods': [
            {
                'flags': m.group(1),
                'name': m.group(2),
                'params': m.group(3),
                'ret': m.group(4),
            }
            for m in METHOD_RE.finditer(text)
        ],
    }


def collect_abstract(class_desc, smali_dirs, seen=None, depth=0):
    '''Gom mọi method abstract cần hiện thực, đi ngược cây kế thừa trong APK.'''
    if seen is None:
        seen = set()
    if class_desc in seen or depth > 8 or class_desc == 'Ljava/lang/Object;':
        return {}
    seen.add(class_desc)
    path = find_class_file(class_desc, smali_dirs)
    if not path:
        return {}
    info = parse_class(path)
    out = {}
    for parent in [info['super']] + info['interfaces']:
        out.update(collect_abstract(parent, smali_dirs, seen, depth + 1))
    for m in info['methods']:
        key = f"{m['name']}({m['params']}){m['ret']}"
        if 'abstract' in m['flags']:
            out[key] = m
            continue
        out.pop(key, None)
    return out


def default_body(ret, string_value=''):
    '''Thân method trả giá trị mặc định theo kiểu trả về.'''
    if ret == 'V':
        return '    .locals 0\n    return-void'
    if ret in ('J', 'D'):
        return '    .locals 2\n    const-wide/16 v0, 0x0\n    return-wide v0'
    if ret in ('Z', 'B', 'S', 'C', 'I', 'F'):
        return '    .locals 1\n    const/4 v0, 0x0\n    return v0'
    if ret == STR_DESC:
        return ('    .locals 1\n    const-string v0, "%s"\n'
                '    return-object v0' % string_value)
    return '    .locals 1\n    const/4 v0, 0x0\n    return-object v0'


def generate(target_desc, stub_desc, smali_dirs, overrides=None, int_values=None):
    '''
    Sinh mã smali cho class stub.

    target_desc : class/interface gốc, ví dụ 'Lcom/applovin/mediation/MaxAd;'
    stub_desc   : tên class stub sẽ tạo, ví dụ 'Ladfree/stub/MaxAd;'
    overrides   : {"tênMethod(params)ret": ["dòng smali", ...]} — thân tự viết
    int_values  : {"tênMethod": số} — method trả số nguyên trả giá trị chỉ định
    '''
    if not overrides:
        overrides = {}
    if not int_values:
        int_values = {}
    path = find_class_file(target_desc, smali_dirs)
    if not path:
        return None
    info = parse_class(path)
    is_iface = 'interface' in info['flags']
    lines = ['.class public %s' % stub_desc]
    if is_iface:
        lines += ['.super Ljava/lang/Object;', '.implements %s' % target_desc]
        super_desc = 'Ljava/lang/Object;'
    else:
        lines += ['.super %s' % target_desc]
        super_desc = target_desc
    lines += [
        '',
        '.method public constructor <init>()V',
        '    .locals 0',
        '    invoke-direct {p0}, %s-><init>()V' % super_desc,
        '    return-void',
        '.end method',
        '',
    ]
    for key, m in sorted(collect_abstract(target_desc, smali_dirs).items()):
        decl = '.method public %s(%s)%s' % (m['name'], m['params'], m['ret'])
        if key in overrides:
            body = '\n'.join(overrides[key])
        elif m['ret'] in ('I', 'J') and m['name'] in int_values:
            v = int_values[m['name']]
            body = ('    .locals 2\n    const-wide/16 v0, %#x\n    return-wide v0' % v
                    if m['ret'] == 'J' else
                    '    .locals 1\n    const/16 v0, %#x\n    return v0' % v)
        elif m['ret'] == STR_DESC and m['name'] in ('getType', 'getLabel'):
            body = default_body(m['ret'], 'reward')
        else:
            body = default_body(m['ret'])
        lines += [decl, body, '.end method', '']
    return '\n'.join(lines) + '\n'


def write_stub(smali_out_dir, stub_desc, code):
    '''Ghi file stub vào thư mục smali chỉ định.'''
    rel = stub_desc[1:-1] + '.smali'
    p = Path(smali_out_dir) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code, encoding='utf-8')
    return p
