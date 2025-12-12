#!/bin/bash

# Support.php dosyasını sunucuya yükleme scripti
# Kullanım: ./upload_support.sh

echo "📤 support.php dosyası sunucuya yükleniyor..."

# Sunucu bilgileri
SERVER="root@89.252.152.125"
REMOTE_PATH="/var/www/html/unipanel/marketing/support.php"
LOCAL_FILE="marketing/support.php"

# Dosya var mı kontrol et
if [ ! -f "$LOCAL_FILE" ]; then
    echo "❌ Hata: $LOCAL_FILE dosyası bulunamadı!"
    exit 1
fi

# SSH ile dosyayı yükle
echo "🔐 Sunucuya bağlanılıyor..."
echo "📝 Şifre: 651CceSl"
echo ""

# Dosyayı base64 encode edip SSH üzerinden yaz
cat "$LOCAL_FILE" | ssh "$SERVER" "mkdir -p /var/www/html/unipanel/marketing && cat > $REMOTE_PATH && chmod 644 $REMOTE_PATH && echo '✅ Dosya başarıyla yüklendi!'"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Başarılı! Dosya sunucuya yüklendi."
    echo "🌐 Test URL: https://foursoftware.com.tr/unipanel/marketing/support.php"
else
    echo ""
    echo "❌ Hata: Dosya yüklenemedi. Lütfen manuel olarak yükleyin:"
    echo "   scp $LOCAL_FILE $SERVER:$REMOTE_PATH"
fi





