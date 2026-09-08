# AdFree Web — ảnh Docker chứa sẵn mọi thứ để chạy cả hai chế độ.
#
# Chế độ chỉ-phân-tích không cần gì ngoài Python, nhưng chế độ chặn quảng cáo
# cần apktool chạy trên Java để tháo/ráp APK — nên ảnh này dựa trên JRE.
#
# Build:  docker build -t adfree -f adfree/Dockerfile .
# Chạy :  docker run --rm -p 8742:8742 adfree
#         rồi mở http://localhost:8742
#
# Lưu ý: ảnh này KHÔNG kèm Android build-tools (apksigner/zipalign) vì giấy phép
# Android SDK hạn chế phát hành lại. Thiếu chúng thì APK chỉ được ký v1 bằng
# jarsigner — Android 11 trở lên có thể từ chối cài. Muốn ký v2/v3, mount
# build-tools từ máy chủ vào rồi trỏ biến ANDROID_BUILD_TOOLS vào đó:
#
#   docker run --rm -p 8742:8742 \
#     -v "$HOME/Library/Android/sdk/build-tools/34.0.0:/opt/build-tools:ro" \
#     -e ANDROID_BUILD_TOOLS=/opt/build-tools adfree

FROM eclipse-temurin:17-jdk-jammy

ARG APKTOOL_VERSION=2.9.3
ENV PORT=8742 \
    APKTOOL=/opt/apktool.jar \
    ADFREE_KEYSTORE=/data/keystore.jks \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# python3 để chạy server; curl chỉ dùng lúc build để tải apktool
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 curl ca-certificates \
 && curl -fsSL -o /opt/apktool.jar \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# hermes_dec là parser HBC thuần Python, adfree/ là server + giao diện
COPY src/hermes_dec /app/src/hermes_dec
COPY adfree/*.py adfree/*.json /app/adfree/
COPY adfree/static /app/adfree/static

# jobs/ và keystore ghi ra volume để khởi động lại không mất
VOLUME ["/data"]
RUN mkdir -p /data && ln -s /data/jobs /app/adfree/jobs

EXPOSE 8742
# mặc định server chỉ nghe 127.0.0.1; trong container phải nghe mọi giao diện
ENV ADFREE_HOST=0.0.0.0
CMD ["python3", "adfree/server.py"]
