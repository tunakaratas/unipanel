#!/bin/bash

# UniPanel Otomatik Sunucu Kurulum Scripti
# Kullanım: ./otomatik_kurulum.sh

SERVER="root@89.252.152.125"
PASSWORD="651CceSl"

echo "🚀 UniPanel Sunucu Kurulumu Başlatılıyor..."

# SSH ile bağlan ve komutları çalıştır
sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $SERVER << 'ENDSSH'
    echo "📥 Git kontrol ediliyor..."
    if ! command -v git &> /dev/null; then
        echo "Git kuruluyor..."
        apt-get update && apt-get install -y git
    fi
    
    echo "📁 Web dizinine gidiliyor..."
    cd /var/www/html
    
    echo "🔄 Eski proje yedekleniyor (varsa)..."
    if [ -d "unipanel" ]; then
        mv unipanel unipanel_backup_$(date +%Y%m%d_%H%M%S)
        echo "✅ Yedek oluşturuldu"
    fi
    
    echo "📥 GitHub'dan proje çekiliyor..."
    git clone https://github.com/tunakaratas/unipanel.git
    cd unipanel
    
    echo "📁 Dosya izinleri ayarlanıyor..."
    chmod -R 755 storage/ logs/ communities/ 2>/dev/null || true
    chmod 644 .htaccess 2>/dev/null || true
    
    echo "📦 Storage klasörleri oluşturuluyor..."
    mkdir -p storage/databases
    mkdir -p storage/uploads
    mkdir -p storage/cache
    chmod -R 755 storage/
    
    echo "⚙️ Config dosyası oluşturuluyor..."
    if [ ! -f "config/credentials.php" ]; then
        cp config/credentials.example.php config/credentials.php
        echo "✅ Config dosyası oluşturuldu"
    else
        echo "ℹ️ Config dosyası zaten var"
    fi
    
    echo "🔍 PHP kontrol ediliyor..."
    php -v
    php -m | grep -i sqlite || echo "⚠️ SQLite extension kontrol edilmeli"
    
    echo ""
    echo "✅ Kurulum tamamlandı!"
    echo "📝 Sonraki adımlar:"
    echo "   1. config/credentials.php dosyasını düzenle ve API anahtarlarını ekle"
    echo "   2. https://yourdomain.com/superadmin/ adresine git"
    echo "   3. Varsayılan giriş: superadmin / SuperAdmin2024!"
    echo "   4. İlk girişten sonra şifrenizi değiştirin!"
ENDSSH

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Kurulum başarıyla tamamlandı!"
else
    echo ""
    echo "❌ Kurulum sırasında hata oluştu"
    echo "Manuel olarak bağlanıp komutları çalıştırabilirsiniz:"
    echo "ssh root@89.252.152.125"
fi

