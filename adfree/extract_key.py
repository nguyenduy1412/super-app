'''
Trích khóa giải mã server thật của Kiwi VPN bằng Frida.

Chạy khi máy ảo/điện thoại đã cài BẢN GỐC Kiwi VPN, đã bật frida-server, và
đã root. Script tự attach, hook adsid()/c(), tự bấm Connect qua adb, rồi in ra
giá trị adsid() cùng chuỗi khóa đầy đủ.

Dùng:
    <venv>/bin/python extract_key.py
'''
import subprocess
import sys
import time
import frida

PKG = 'kiwivpn.connectip.ipchanger.unblocksites'
ADB = subprocess.run(['bash', '-lc', 'echo $HOME'],
                     capture_output=True, text=True).stdout.strip()
ADB = f'{ADB}/Library/Android/sdk/platform-tools/adb'

HOOK = '''
Java.perform(function () {
  var X = Java.use("com.fast.vpn.util.X509Utils");
  X.adsid.implementation = function () {
    var r = this.adsid();
    send({ tag: "adsid", value: r });
    return r;
  };
  X.c.overload("java.lang.String", "java.lang.String").implementation = function (data, key) {
    send({ tag: "key", key: key });
    return this.c(data, key);
  };
  send({ tag: "ready" });
});
'''


def adb(*args):
    subprocess.run([ADB, *args], capture_output=True, text=True)


def main():
    adb('shell', 'pm', 'clear', PKG)
    adb('shell', 'monkey', '-p', PKG,
        '-c', 'android.intent.category.LAUNCHER', '1')
    time.sleep(7)
    dev = frida.get_usb_device(timeout=10)
    pid = dev.get_process(PKG).pid if hasattr(dev, 'get_process') else dev.spawn([PKG])
    session = dev.attach(pid)
    script = session.create_script(HOOK)
    results = {}

    def on_message(message, data):
        if message.get('type') == 'send':
            payload = message.get('payload', {})
            results[payload.get('tag')] = payload
            print('[frida]', payload)

    script.on('message', on_message)
    script.load()
    if hasattr(dev, 'resume'):
        dev.resume(pid)
    # Bấm nút Connect qua tap trung tâm màn hình
    adb('shell', 'input', 'tap', '540', '1400')
    time.sleep(15)
    print('=== KẾT QUẢ ===')
    print('adsid :', results.get('adsid', {}).get('value'))
    print('key   :', results.get('key', {}).get('key'))
    session.detach()


if __name__ == '__main__':
    main()
