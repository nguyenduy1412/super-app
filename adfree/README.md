Chunk ID: bf7621
Wall time: 0.0000 seconds
Process exited with code 0
Original token count: 1313
Output:
# AdFree — xóa quảng cáo APK qua web (tự host)

Tái hiện tính năng "Remove Ads" của Lucky Patcher thành web app không cần root:
**upload APK → nhận APK đã vô hiệu hóa SDK quảng cáo**.

## Chạy

```bash
cd adfree
python3 server.py          # mở http://localhost:8742
```

Yêu cầu: Python 3, Java 17+, `apktool.jar` (mặc định lấy `../apktool.jar`),
Android SDK build-tools (`~/Library/Android/sdk/build-tools/…` — có apksigner + zipalign).

### CLI (không cần web)

```bash
python3 patcher.py input.apk               # tạo input-adfree.apk
python3 patcher.py input.apk out.apk       # chỉ định tên file ra
python3 patcher.py input.apk --no-reward   # chỉ xóa ads, tắt bấm-là-nhận-quà
python3 patcher.py input.apk --no-offline  # tắt chế độ ép-SDK-nghĩ-offline
```

## 🎁 Bấm là nhận quà (bật sẵn)

Với chức năng đòi *"xem quảng cáo mới mở khoá"*, tool làm 3 việc:

1. **Ép trạng thái sẵn sàng** — mọi hàm `isReady`/`isLoaded`/`canPlayAd`/`isValid`…
   của SDK quảng cáo trả về `true`, nên nút bấm luôn bật, không phải chờ tải.
2. **Sinh "phần thưởng giả"** — [stubgen.py](stubgen.py) đọc chính interface trong
   APK (`RewardItem`, `MaxAd`, `MaxReward`…) rồi tự sinh class hiện thực đầy đủ.
   Nhờ có đối tượng thật (không phải `null`), code Kotlin kiểm tra non-null không
   crash.
3. **Gọi thẳng callback thành công** — thân `show()`/`load()` được thay bằng lệnh
   gọi ngay `onUserEarnedReward` / `onUnityAdsShowComplete(COMPLETED)` /
   `onUserRewarded` → app tưởng người dùng đã xem hết quảng cáo và trao thưởng
   ngay khi bấm. Có cờ chống gọi lồng nhau vô hạn (`Holder.busy`).

Luật khai báo trong [reward_patches.json](reward_patches.json), khớp theo **chữ ký
method** chứ không theo tên class — nên vẫn đúng khi SDK đổi tên class nội bộ giữa
các phiên bản.

## 📴 Ép SDK nghĩ offline (bật sẵn)

Mượn chiến lược *Offline patch* của Lucky Patcher: [offlinepatch.py](offlinepatch.py)
tiêm class hook `adfree.hook.OfflineHook` vào APK rồi **đổi mọi lệnh gọi API kiểm
tra mạng của Android** (`ConnectivityManager.getActiveNetworkInfo`,
`NetworkInfo.isConnected`, `isConnectedOrConnecting`, `isAvailable`,
`getActiveNetwork`, `getNetworkCapabilities`) trong code SDK quảng cáo thành lệnh
gọi hook — luôn trả lời "không có mạng". SDK nhìn đâu cũng thấy offline nên bỏ qua
tải ads, trong khi app vẫn dùng mạng bình thường vì chỉ code SDK bị đổi.

Chỉ áp cho file smali của SDK đã được phát hiện — code của app không bị đụng tới,
nên app vẫn báo "mất kết nối" đúng khi thật sự mất mạng.

## Cách hoạt động

1. **Decode** APK bằng apktool.
2. **Quét** 27 SDK quảng cáo (AdMob, Meta Audience Network, AppLovin, Unity Ads,
   Vungle, ironSource, MoPub, AppNext, InMobi, Amazon, StartApp, myTarget,
   Pangle, Mintegral, AdColony, Tapjoy, Fyber, PubNative, Smaato, GDT, Ogury,
   Yandex, AdMost, Kwai, BidMachine…) theo danh sách [ad_signatures.json](ad_signatures.json).
3. **Vô hiệu hóa**: thay thân các method khởi tạo/tải quảng cáo (`initialize`,
   `loadAd`, `show`…) bằng lệnh return sớm → SDK "chạy" nhưng không tải được ads.
   Đồng thời xóa các activity/service/receiver quảng cáo (AdActivity…) và các
   quyền `AD_ID`, `ACCESS_ADSERVICES_*` khỏi AndroidManifest.
4. **Ép offline**: đổi lệnh kiểm tra mạng trong code SDK sang hook luôn báo
   "không có Internet" — lớp chặn thứ hai cho SDK nào lọt qua bước 3.
5. **Build lại** + **zipalign** + **ký v2/v3** bằng keystore tự tạo
   (`keystore.jks` sinh lần chạy đầu, đổi qua biến môi trường `ADFREE_*`).

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PORT` | 8742 | cổng web |
| `APKTOOL` | `../apktool.jar` | đường dẫn apktool.jar |
| `ANDROID_BUILD_TOOLS` | tự tìm trong SDK | thư mục chứa apksigner/zipalign |
| `ADFREE_KEYSTORE` / `ADFREE_KEY_ALIAS` / `ADFREE_KEY_PASS` | `keystore.jks` / `adfree` / `adfree-key` | khóa ký APK |
| `ADFREE_MAX_UPLOAD` | 512 MB | giới hạn file upload |

## Giới hạn & lưu ý

- Không dùng được với app đóng gói sẵn `classes.dex` đã mã hóa, APK split
  (`.xapk`/`.apks`), hoặc app có kiểm tra chữ ký tự hủy — sẽ cần patch thêm.
- App vẫn giữ class quảng cáo (chỉ method bị rỗng) nên không crash do layout
  XML tham chiếu `AdView`.
- Chế độ bấm-là-nhận-quà hiện phủ AdMob, Unity Ads và AppLovin MAX (3 SDK
  rewarded phổ biến nhất, và cũng là lớp mediation nên phủ luôn mạng con bên
  dưới). SDK rewarded khác chỉ được ép `isReady=true`, chưa gọi callback.
- **Chỉ dùng cho nghiên cứu hoặc ứng dụng của chính bạn.** Phân phối APK đã
  chỉnh sửa của bên thứ ba vi phạm điều khoản dịch vụ và có thể vi phạm pháp luật.