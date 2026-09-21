#!/bin/zsh
# Super App launcher — bật TẤT CẢ server của bộ Super App:
#   1) AdFree APK server   (cổng 8742, chạy nền)
#   2) NetFence LAN server (cổng 8748, chạy nền)
#   3) Main server         (GitKraken Web + Mac App Mover, cổng 8765, foreground + tự mở trình duyệt)
# Main server redirect tab AdFree -> :8742 và tab NetFence -> :8748 nên 2 server đó phải chạy trước.

DIR="/Volumes/Razer/code/superapp"
cd "$DIR" || { echo "Khong tim thay $DIR"; exit 1; }

# Mỗi server của dự án khai báo ở đây theo dạng "thu-muc:cong:ten".
# Muốn server mới luôn được bật cùng Super App thì chỉ cần thêm một dòng.
SERVICES=(
  "adfree:8742:AdFree"
  "netfence:8748:NetFence"
)
declare -A SERVICE_PIDS

# NetFence cần đọc bảng ARP — trên macOS 15+/27, Homebrew Python thường bị
# Local Network Privacy chặn (`arp -an` rỗng / MAC giả 02:00:00:00:00:00).
# Luôn dùng Python hệ thống (Apple-signed) và KHÔNG tái sử dụng process cũ.
PYTHON_NETFENCE="/usr/bin/python3"
PYTHON_DEFAULT="${PYTHON:-python3}"

kill_port() {
  local port="$1"
  local pids
  pids=$(/usr/sbin/lsof -t -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    echo "→ Dang tat process cu tren cong $port (pid: $pids)..."
    kill $pids 2>/dev/null || true
    for _ in {1..20}; do
      /usr/sbin/lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || break
      sleep 0.1
    done
    pids=$(/usr/sbin/lsof -t -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
      kill -9 $pids 2>/dev/null || true
      sleep 0.2
    fi
  fi
}

start_bg() {  # $1=port  $2=nhãn  $3=thư mục con
  local port="$1" label="$2" sub="$3"
  local py="$PYTHON_DEFAULT"
  if [[ "$sub" == "netfence" ]]; then
    py="$PYTHON_NETFENCE"
    # Process cũ (thường do Homebrew Python) có thể vẫn listen nhưng không đọc được ARP.
    kill_port "$port"
  elif /usr/sbin/lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then
    echo "✓ $label da chay san tren cong $port."
    return 1
  fi
  echo "→ Dang bat $label server (cong $port) bang $py..."
  ( cd "$DIR/$sub" && exec "$py" server.py ) >/tmp/superapp_${sub}.log 2>&1 &
  SERVICE_PIDS[$sub]=$!
  return 0
}

cleanup() {
  local sub pid
  for sub pid in ${(kv)SERVICE_PIDS}; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo "→ Tat ${sub} server nen (pid $pid)..."
      kill "$pid" 2>/dev/null
    fi
  done
}
trap cleanup EXIT INT TERM

for spec in "${SERVICES[@]}"; do
  IFS=':' read -r sub port label <<< "$spec"
  start_bg "$port" "$label" "$sub" || true
done

# Cho các server phụ sẵn sàng trước khi mở UI chính, tránh redirect vào trang chết.
for spec in "${SERVICES[@]}"; do
  IFS=':' read -r sub port label <<< "$spec"
  for _ in {1..30}; do
    /usr/sbin/lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1 && break
    sleep 0.1
  done
done

echo "→ Bat main server (GitKraken Web + Mac App Mover)..."
echo "============================================================"
# Foreground: server nay se tu mo trinh duyet va giu tien trinh song.
exec python3 server.py
