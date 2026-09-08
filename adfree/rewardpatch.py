'''
Giả lập "đã xem xong quảng cáo".

Với các chức năng đòi xem quảng cáo mới mở khoá, module này:
  1. Ép mọi hàm kiểm tra "quảng cáo đã sẵn sàng chưa" trả về true — nút bấm
     luôn bật.
  2. Thay thân hàm show()/load() của SDK bằng lệnh gọi thẳng callback thành
     công, kèm đối tượng phần thưởng hợp lệ do stubgen sinh ra — bấm phát là
     nhận quà, app vẫn tưởng người dùng đã xem hết quảng cáo.

Luật khai báo trong reward_patches.json, khớp theo **chữ ký method** chứ không
theo tên class — nên vẫn đúng khi SDK đổi tên class nội bộ giữa các phiên bản.
'''
import json
import re
from pathlib import Path
import stubgen

PATCH_FILE = Path(__file__).resolve().parent / 'reward_patches.json'
DECL_RE = re.compile(
    r'^\.method\s+([^\n]*?)\s*\b([^\s(]+)\(([^)]*)\)(\S+)\s*$', re.M)


def _replace_body(text, decl_match, body_lines):
    '''Thay thân method (từ sau .method tới .end method) bằng body_lines.'''
    end = text.find('.end method', decl_match.end())
    if end == -1:
        return None
    body = '\n'.join(body_lines)
    return (text[:decl_match.start()] + decl_match.group(0) + '\n'
            + body + '\n.end method' + text[end + len('.end method'):])


def _iter_package_files(decoded, smali_dirs, packages):
    '''Sinh ra từng file .smali nằm trong các package chỉ định.'''
    decoded = Path(decoded)
    for pkg in packages:
        rel = Path(pkg)
        for sd in smali_dirs:
            d = Path(sd) / rel
            if d.is_dir():
                for p in sorted(d.rglob('*.smali')):
                    yield p


def _load_rules():
    if not PATCH_FILE.exists():
        return []
    try:
        data = json.loads(PATCH_FILE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return []
    return data.get('rules', [])


def _show_body(rule, params):
    '''
    Sinh thân show(): gọi thẳng callback thành công trên listener.

    Listener là tham số interface đầu tiên khớp listener_desc trong rule.
    Phần thưởng: new-instance stub class do stubgen sinh ra trước đó.
    '''
    # Tìm thanh ghi listener: p0=this nếu không static, tiếp theo theo tham số
    listener_reg = None
    idx = 0
    is_static = ' static' in rule.get('_flags', '')
    if not is_static:
        idx = 1  # p0 = this
    desc = params
    i = 0
    reg = 1 if not is_static else 0
    listener_desc = rule.get('listener', '')
    while i < len(desc):
        ch = desc[i]
        size = 2 if ch in 'JD' else 1
        # descriptor bắt đầu tại vị trí i
        candidate = desc[i:]
        if listener_desc and candidate.startswith(listener_desc):
            listener_reg = reg
            break
        if ch == 'L':
            i = desc.index(';', i) + 1
        elif ch == '[':
            j = i
            while desc[j] == '[':
                j += 1
            if desc[j] == 'L':
                i = desc.index(';', j) + 1
            else:
                i = j + 1
        else:
            i += 1
        reg += size
    if listener_reg is None:
        return None

    callback = rule['callback']
    listener_desc_full = listener_desc or ''
    reward_stub = rule.get('reward_stub')
    call_args = [f'v{listener_reg}']
    obj_regs = []
    lines = []
    if reward_stub:
        # new-instance + constructor cho stub phần thưởng (thanh ghi cao hơn)
        obj_reg = listener_reg + 1
        lines += [
            f'    new-instance v{obj_reg}, {reward_stub}',
            f'    invoke-direct {{v{obj_reg}}}, {reward_stub}-><init>()V',
        ]
        obj_regs.append(f'v{obj_reg}')
    arg_list = ', '.join(['{' + ', '.join(call_args + obj_regs) + '}'])
    lines.append(
        f'    invoke-interface {{v{listener_reg}{(", " + ", ".join(obj_regs)) if obj_regs else ""}}}, '
        f'{listener_desc_full}->{callback}({rule.get("callback_params", "")})'
        f'{rule.get("callback_ret", "V")}')
    lines.append('    return-void')
    return lines


def apply(decoded, detection, smali_dirs, log):
    '''
    Áp các luật reward-patch lên smali của SDK.

    Trả về report: {enabled, rules_applied, methods_patched}
    '''
    rules = _load_rules()
    if not rules:
        log.append('[reward] Bỏ qua — không có reward_patches.json.')
        return {'enabled': False, 'methods_patched': 0}

    patched = 0
    rule_hits = {}
    for rule in rules:
        method = rule.get('method')
        if not method:
            continue
        files = list(_iter_package_files(decoded, smali_dirs,
                                         rule.get('packages', [])))
        for path in files:
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            new = text
            for m in DECL_RE.finditer(text):
                name, params, ret = m.group(2), m.group(3), m.group(4)
                if name != method:
                    continue
                if 'abstract' in m.group(1) or 'native' in m.group(1):
                    continue
                if rule.get('ready'):
                    body = ['    const/4 v0, 0x1', '    return v0'] \
                        if ret in ('Z', 'I') else ['    const/4 v0, 0x1', '    return v0']
                elif rule.get('callback'):
                    rule['_flags'] = m.group(1)
                    body = _show_body(rule, params)
                    if body is None:
                        continue
                else:
                    continue
                replaced = _replace_body(new, m, body)
                if replaced is not None:
                    new = replaced
                    patched += 1
                    rule_hits[rule.get('name', method)] = \
                        rule_hits.get(rule.get('name', method), 0) + 1
            if new != text:
                path.write_text(new, encoding='utf-8')
    log.append(f'[reward] Đã vá {patched} method reward '
               f'({len(rule_hits)} luật khớp).')
    return {'enabled': True, 'methods_patched': patched,
            'rules': rule_hits}
