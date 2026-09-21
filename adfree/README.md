# AdFree — xóa quảng cáo & dịch ngôn ngữ APK qua web (tự host)

Tái hiện tính năng "Remove Ads" của Lucky Patcher thành web app không cần root:
**upload APK → nhận APK đã vô hiệu hóa SDK quảng cáo**.

Ngoài ra: **dịch ngôn ngữ APK** (string resources sang 49 ngôn ngữ bằng model
dịch chạy offline ngay trên máy) và **phân tích tài nguyên** bên trong APK.

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

### 🌐 Dịch ngôn ngữ APK

Đầu vào **1 file APK**, đầu ra **1 file APK đã dịch + ký sẵn** (cài được ngay).
Bật toggle **Dịch ngôn ngữ**, chọn ngôn ngữ đích → APK đầu ra luôn hiển thị
ngôn ngữ đã chọn **bất kể ngôn ngữ máy**. Kết hợp được với chặn quảng cáo trong
cùng một lần xử lý.

Dịch chạy **hoàn toàn trên máy** — không gửi text của app đi đâu cả. Lần đầu
cần mạng để backend tự tải bộ dịch offline ([offline_mt.py](offline_mt.py)):

| Tải về | Dung lượng | Nơi lưu |
|---|---|---|
| Runtime `ctranslate2` + `sentencepiece` | ~60 MB | `~/.adfree/mt/runtime-pyXY` (venv riêng) |
| Model dịch mỗi cặp ngôn ngữ | ~80 MB | `~/.adfree/mt/models/` |

Runtime được `pip install` vào venv riêng rồi nạp thẳng vào process đang chạy
— không đụng Python hệ thống, và **không** cần thư viện `argostranslate` (thư
viện đó kéo theo torch/spacy ~1 GB, ở đây chỉ cần đúng 2 gói để chạy model).
Model là file `.argosmodel` của Argos OpenTech (49 ngôn ngữ). Sau lần đầu, mọi
lần dịch sau chạy offline. Model đã cài bằng `argospm` ở
`~/.local/share/argos-translate/packages` cũng được dùng lại, không tải trùng.

Chuẩn bị sẵn trước khi dịch (không bắt buộc):

```bash
python3 offline_mt.py status         # runtime/model đã có gì, tốn bao nhiêu đĩa
python3 offline_mt.py install vi     # tải trước runtime + model en→vi
python3 offline_mt.py langs          # 49 ngôn ngữ có model
python3 offline_mt.py tr vi "Watch ad to unlock"
```

Cách hoạt động ([translator.py](translator.py)):

1. Đọc string resources từ `res/values/` (locale mặc định) sau khi apktool
   decode — đây là nơi chứa mọi text giao diện của app.
2. Bỏ qua: `translatable="false"`, tham chiếu `@string/…`, URL, email, chuỗi
   không có chữ cái.
3. Dịch bằng model offline. Placeholder `%1$s`/`%d`, tag `<b>`/`<i>`, escape
   `\n` được tách thành token `[0]`, `[1]`… trước khi dịch rồi ghép lại —
   engine làm rơi token nào thì chuỗi đó giữ nguyên bản gốc (an toàn hơn là
   gãy layout), và khoảng trắng engine tự chèn quanh token bị bỏ để `<b>%d</b>`
   không thành `<b> %d </b>`.
4. Index model chỉ có các cặp đi qua tiếng Anh, nên cặp không có model trực
   tiếp tự dịch 2 chặng: app Trung Quốc (chuỗi Hán >25% → tự nhận nguồn `zh`)
   dịch `zh→en→vi`.
5. **Không dịch chuỗi cấu hình**: resource tên kiểu `google_api_key`,
   `google_app_id`, `project_id`, `*_bucket`, `*_client_id`… và mọi giá trị
   kiểu định danh (một từ liền có chữ số hoặc `. _ : /` — `androidx.startup`,
   `english-grammar-test.appspot.com`) bị bỏ qua. Gặp thật: model dịch
   `AIzaSy…` thành `AlzaSy…`, `1:…:android:…` thành `1:…: Andero:…`,
   `english-grammar-test.appspot.com` thành `Name` → **Firebase không init
   được, app crash**.
6. **Van an toàn**: bản dịch bị loại (giữ nguyên gốc) nếu nó bắt đầu bằng
   `@`/`?` mà bản gốc không — aapt2 đọc đó là tham chiếu `@string/…` /
   `?attr/…` và **build vỡ cả APK** — hoặc nếu nó mất sạch chữ, chỉ còn `?`
   và dấu câu (engine gặp ký tự không encode được). Cả hai đã gặp thật khi
   dịch một mảng tên nước tiếng Ba Tư sang tiếng Nhật.
7. Ghi vào `res/values/` và **gỡ string khỏi các folder `values-en`,
   `values-vi`…** để chúng không override bản dịch khi ngôn ngữ máy trùng.
   Màu/kích thước trong các folder đó giữ nguyên.
8. Build lại + zipalign + ký như pipeline chặn quảng cáo.

Kết quả dịch cache ở `translation_cache.json` — APK sau dùng lại ngay, không
dịch lại những chuỗi trùng.

CLI (APK → APK, chỉ dịch, không vá ads):

```bash
python3 translator.py input.apk vi             # tạo input-vi.apk
python3 translator.py input.apk ja out-jp.apk  # tiếng Nhật, chỉ định tên ra
```

Test:

```bash
python3 test_translate_real.py      # engine offline thật (lần đầu cần tải model)
python3 test_translate_offline.py   # mock kết quả dịch, không cần mạng
```

### 🧬 Nhận diện công nghệ & dịch đúng kho text

Text giao diện nằm ở chỗ khác nhau tuỳ công nghệ, nên trước khi dịch tool
**phân loại app rồi kiểm kê từng kho text** ([apptech.py](apptech.py) — dùng
lại phần nhận diện của [techinfo.py](techinfo.py)). Một app có thể dùng nhiều
thứ cùng lúc (vỏ Kotlin + màn hình React Native + mini-game Unity) nên kết quả
là **danh sách** kho text, không phải một loại duy nhất.

```bash
python3 apptech.py app.apk            # app dùng gì, text ở đâu, dịch được không
python3 apptech.py app.apk --json
```

| Kho text | Công nghệ | Trạng thái |
|---|---|---|
| `res/values/*.xml` | Kotlin/Java + XML | ✅ [translator.py](translator.py) |
| Hermes bytecode `assets/index.android.bundle` | React Native ≥ 0.70 | ✅ [hbc_strings.py](hbc_strings.py) |
| **catalog i18n nhúng trong bundle** (JSON kiểu Lingui/i18next) | React Native | ✅ [deep_translate.py](deep_translate.py) |
| JS bundle dạng text | React Native cũ (JSC) | ✅ [deep_translate.py](deep_translate.py) |
| JSON/ARB/XML/properties/PO/CSV trong `assets/` | Flutter có file i18n, Cordova/Capacitor, **engine tự viết** | ✅ [deep_translate.py](deep_translate.py) |
| `const-string` trong code | Kotlin/Java hardcode text | ✅ [smali_strings.py](smali_strings.py) (bật `X-Translate-Code`) |
| `TextAsset` + bảng Unity Localization | Unity | ✅ [unity_strings.py](unity_strings.py) |
| `global-metadata.dat` | Unity IL2CPP | ✅ [il2cpp_strings.py](il2cpp_strings.py) (chỉ version chuẩn) |
| Dữ liệu nội dung app (JSON câu hỏi/bài học) | mọi nền tảng | 🟡 phải chọn (`X-Translate-Data`) — dịch nội dung có thể phá app |
| `libapp.so` (Dart AOT) | Flutter không có file i18n | ❌ xem lý do bên dưới |
| `assemblies/*.dll` | .NET MAUI / Xamarin | ❌ chưa làm |
| `.pak`/`.locres` | Unreal Engine | ❌ chưa làm |

Kho ❌ vẫn được **báo rõ trong kết quả kèm lý do** — biết ngay vì sao app này
dịch không ăn, thay vì tưởng tool hỏng.

#### React Native / Hermes

Từ RN 0.70, JS được biên dịch thành Hermes bytecode nên **`res/values` gần như
trống** — đó là lý do dịch app React Native trước đây không thấy gì.
[hbc_strings.py](hbc_strings.py) đọc và **dựng lại** bảng chuỗi của file HBC
(viết riêng theo `BytecodeFileFormat.h` của Hermes, đã kiểm chứng tới HBC v98
= RN 0.79):

- Chuỗi tiếng Việt cần UTF-16 (2 byte/ký tự) nên bảng chuỗi phình ra → mọi
  section sau nó bị dịch chỗ → phải cập nhật `fileLength`, `debugInfoOffset`,
  **offset bytecode của từng function** và con trỏ `LargeFunctionHeader`
  (v98 rút `functionName` xuống 8 bit nên 2/3 function dùng header lớn).
- Chuỗi dài >255 ký tự tự đẩy sang **bảng overflow**.
- Footer SHA1 của file được tính lại.
- **Chỉ dịch chuỗi `kind = String`.** Chuỗi `kind = Identifier` là tên thuộc
  tính/biến JS (`onPress`, `flexDirection`) — đổi là app hỏng ngay.
- Trước khi ghi, `hbc_strings.verify()` kiểm: mọi chuỗi đọc lại đúng, **bytecode
  từng function giống nguyên bản từng byte**, footer + `fileLength` khớp. Không
  pass thì **giữ bundle gốc** chứ không xuất APK mở lên là crash.

Trong bundle JS, chuỗi `kind=String` lẫn lộn rất nhiều thứ không phải text UI:
tên icon (`LucideMap`), class tailwind (`size-9 items-center`), hash
(`hckbmu`), tên hàm nội bộ (`onSettledFulfill`), giá trị enum (`italic`,
`no-store`). `translator.natural_text()` chỉ nhận chuỗi trông như câu chữ:

- bỏ camelCase/PascalCase, chuỗi có `_ / \ | < > { } # $ = @`, có chữ dính số
- bỏ danh sách class CSS (`-9`, `gap-1.5`), token nối gạch chiếm quá nửa
- bỏ id ngẫu nhiên (4 phụ âm liền nhau), ALLCAPS
- bỏ chuỗi **khác hệ chữ với ngôn ngữ nguồn** — bundle RN hay nhúng sẵn catalog
  i18n tiếng Hy Lạp/Ba Tư/Séc của thư viện, đưa vào model en→vi chỉ ra rác
- **mặc định chỉ dịch chuỗi nhiều từ**: chuỗi một từ trong bundle JS phần lớn
  là enum/CSS/tên component, dịch là sai *logic* chứ không chỉ sai chữ. Bật
  `ADFREE_RN_SINGLE_WORD=1` để dịch cả chuỗi một từ (được nhiều text UI hơn,
  rủi ro hơn).

Xem trước sẽ dịch gì mà không ghi file:

```bash
python3 deep_translate.py app.apk vi --preview
```

Dịch + ký, **không cần apktool** (sửa thẳng trong file zip nên nhanh và không
có rủi ro aapt2 build lỗi):

```bash
python3 deep_translate.py app.apk vi out.apk
```

Chạy qua web hoặc `patcher.py` thì cả hai lớp chạy trong một lần: `res/values`
(qua apktool) rồi Hermes/assets (mức zip) trước khi ký.

Chuỗi dài bị model dịch cụt (mất hẳn câu sau) nên chuỗi >60 ký tự được **cắt
theo câu**, dịch từng câu rồi ghép lại. Bản dịch cụt/suy biến (ít hơn 45% số từ
so với bản gốc) bị loại, giữ nguyên bản gốc.

Test:

```bash
python3 test_hbc.py app.apk       # đọc/ghi lại bảng chuỗi Hermes trên bundle thật
```

#### Unity

`TextAsset` (file JSON/CSV localization đóng trong asset) và bảng của package
Unity Localization được sửa qua **UnityPy** — tự cài vào cùng venv với engine
dịch. Bảng MonoBehaviour chỉ đọc/ghi được khi file còn TypeTree (build không
strip), không có thì bỏ qua và báo rõ.

Chuỗi literal của C# nằm trong `global-metadata.dat` (build IL2CPP):
[il2cpp_strings.py](il2cpp_strings.py) dựng lại vùng `stringLiteralData` và
cộng delta vào offset của mọi section phía sau trong header. **Chỉ nhận
metadata version chuẩn của Unity** — gặp thật: metadata của Duolingo khai
version 39 (không phải version nào của Unity) tức là đã bị obfuscate, tool từ
chối sửa thay vì phá game.

Rất nhiều game **tải nội dung lúc chạy** (Addressables trên CDN) nên trong APK
không có text nào để dịch — lúc đó báo 0 chuỗi, không phải lỗi.

#### Chuỗi hardcode trong code (dex)

Nhiều app nhét text thẳng vào code. [smali_strings.py](smali_strings.py) sửa
lệnh `const-string` trong smali rồi để apktool build lại dex — an toàn hơn mổ
trực tiếp `classes.dex` (đổi độ dài chuỗi trong dex phải dựng lại cả
`string_ids`). Mặc định **tắt** (`X-Translate-Code: 1` để bật) vì chuỗi trong
code vừa là text hiển thị vừa là khoá/tham số. Bỏ qua code thư viện
(androidx, kotlin, com/google, okhttp, SDK quảng cáo…) và chuỗi đứng cạnh lệnh
kiểu khoá dữ liệu (`->put`, `getString`, `equals`, `SharedPreferences`,
`JSONObject`…).

#### Flutter: dịch động qua Native Hook C++

Text của Flutter nằm trong snapshot Dart AOT (`libapp.so`), không có bảng offset để sửa tĩnh trực tiếp mà không làm vỡ cấu trúc snapshot.

Hệ thống giải quyết bằng cơ chế **Native Hook tại tầng C++ của Flutter Engine (`libflutter.so`)**:
1. [flutter_translate.py](flutter_translate.py) trích xuất chuỗi hiển thị từ `libapp.so`, dịch tự động và lưu vào `assets/flutter_dict.json`.
2. Tự động chèn thư viện C++ [libflutter_hook.so](flutter_hook/) vào `lib/<abi>/` và chèn lệnh nạp library vào smali.
3. Khi app chạy, hook sẽ chặn tại hàm `ParagraphBuilder::addText` của Flutter Engine, tự động tra từ điển và thay bằng tiếng Việt có dấu trước khi vẽ ra màn hình — **hỗ trợ đầy đủ tiếng Việt có dấu, không làm crash snapshot và không cần root máy**.

Bù lại: app Flutter nào có sẵn file i18n (`.arb`/`.json` trong `flutter_assets`) thì dịch trực tiếp ở mức file qua [deep_translate.py](deep_translate.py), và phần `res/values` vẫn dịch như app native.

### Kiểm chứng trên máy thật

Vá bảng chuỗi của Hermes/Unity/IL2CPP là việc dễ làm app crash lúc mở, và lỗi
chỉ hiện khi chạy. [devicetest.py](devicetest.py) tự động hoá vòng kiểm tra:

```bash
python3 devicetest.py app-vi.apk                    # cài → mở → đọc logcat
python3 devicetest.py app-vi.apk --compare goc.apk  # kiểm cả bản gốc
```

Có `--compare` để biết crash do bản dịch hay do chính bản gốc. Chính nó tìm ra
lỗi thật khi test app React Native đầu tiên: app crash `Invalid supabaseUrl`,
bản gốc thì không → truy ra whatwg-url lưu **trạng thái parser** dưới dạng
chuỗi (`path or authority`, `special authority slashes`) rồi dispatch theo nội
dung chuỗi đó, dịch là `new URL()` vỡ. Luật lọc đã chặn cả nhóm này.

⚠️ `devicetest.py` **gỡ app cũ trước khi cài** (chữ ký khác nên buộc phải vậy)
→ mất dữ liệu/đăng nhập của app đó trên máy.

Test:

```bash
python3 test_hbc.py app.apk          # đọc/ghi bảng chuỗi Hermes (bundle thật)
python3 test_unity.py app.apk        # đọc/ghi TextAsset của Unity
python3 test_il2cpp.py               # đọc/ghi global-metadata.dat (file tự sinh)
python3 test_translate_real.py       # engine dịch offline thật
python3 test_translate_offline.py    # mock, không cần mạng
```

Giới hạn chung: chất lượng dịch là máy dịch offline nên có chỗ ngô nghê; chuỗi
1-2 từ thiếu ngữ cảnh (`Sign in` → `Ký vào`) là điểm yếu rõ nhất. Với app React
Native/Unity, số chuỗi dịch được phụ thuộc app: nhiều app phần lớn chuỗi là
thông báo lỗi của thư viện, hoặc tải text từ server.

Biến môi trường:

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `ADFREE_ENGINE` | `offline` | `offline` = chỉ model local (mặc định) · `google` = chỉ Google Dịch free · `auto` = Google trước, lỗi → offline |
| `ADFREE_SOURCE_LANG` | `auto` | Ngôn ngữ nguồn của app: `auto` tự đoán (Hán >25% → `zh`), hoặc ép `en`/`zh`… |
| `ADFREE_MT_HOME` | `~/.adfree/mt` | Nơi lưu runtime + model dịch |
| `ADFREE_MT_NO_INSTALL` | `0` | `1` = không tự `pip install` runtime (môi trường cấm mạng) |
| `ADFREE_MT_DEVICE` | `cpu` | `cuda` nếu có GPU NVIDIA |
| `ADFREE_RN_SINGLE_WORD` | `0` | `1` = dịch cả chuỗi một từ trong bundle JS/Hermes (nhiều text hơn, rủi ro sai logic hơn) |
| `ADFREE_KEEP` | — | Danh sách từ giữ nguyên, cách nhau bằng dấu phẩy (tên thương hiệu…). Tên app tự được thêm vào |
| `ADFREE_SMALI_ALL` | `0` | `1` = dịch cả chuỗi trong code thư viện (mặc định chỉ code app) |
| `ADFREE_TRANSLATE_DATA` | `0` | `1` = dịch cả dữ liệu nội dung app trong assets |

Web API: `GET /api/mt` trả trạng thái engine dịch (runtime đã cài chưa, model
nào có sẵn, tốn bao nhiêu đĩa, 49 ngôn ngữ hỗ trợ) — UI dùng để đánh dấu
"đã tải" cho từng ngôn ngữ trong danh sách chọn.

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
