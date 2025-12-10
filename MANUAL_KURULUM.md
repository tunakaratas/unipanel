# 🔧 Manuel Sunucu Kurulumu

SSH otomatik bağlantı çalışmadığı için manuel olarak kurulum yapmanız gerekiyor.

## Adım 1: Sunucuya Bağlan

Terminal'de şu komutu çalıştırın:

```bash
ssh root@89.252.152.125
```

Şifre sorulduğunda: `651CceSl`

## Adım 2: Kurulum Komutlarını Çalıştır

Sunucuya bağlandıktan sonra şu komutları sırayla çalıştırın:

```bash
# Git kurulu mu kontrol et
git --version || (apt-get update && apt-get install -y git)

# Web dizinine git
cd /var/www/html

# Eski projeyi yedekle (varsa)
if [ -d "unipanel" ]; then
    mv unipanel unipanel_backup_$(date +%Y%m%d_%H%M%S)
fi

# GitHub'dan projeyi clone et
git clone https://github.com/tunakaratas/unipanel.git
cd unipanel

# Dosya izinlerini ayarla
chmod -R 755 storage/ logs/ communities/
chmod 644 .htaccess

# Storage klasörlerini oluştur
mkdir -p storage/databases
mkdir -p storage/uploads
mkdir -p storage/cache
chmod -R 755 storage/

# Config dosyasını oluştur
cp config/credentials.example.php config/credentials.php

# PHP kontrolü
php -v
php -m | grep sqlite
```

## Adım 3: Config Dosyasını Düzenle

```bash
nano config/credentials.php
```

API anahtarlarını ekleyin (Groq API key vs.)

## Adım 4: Web Server'ı Kontrol Et

```bash
# Apache için
systemctl status apache2
systemctl restart apache2

# veya Nginx için
systemctl status nginx
systemctl restart nginx
```

## Adım 5: İlk Giriş

Tarayıcıda şu adrese gidin:
- `https://yourdomain.com/superadmin/`

Varsayılan giriş bilgileri:
- **Kullanıcı**: `superadmin`
- **Şifre**: `SuperAdmin2024!`

**İlk girişten sonra mutlaka şifrenizi değiştirin!**

## Güncelleme (İleride)

```bash
cd /var/www/html/unipanel
git pull origin main
```

## Sorun Giderme

### 500 Internal Server Error
```bash
tail -f /var/log/apache2/error.log
# veya
tail -f /var/log/nginx/error.log
```

### Dosya İzin Sorunları
```bash
chown -R www-data:www-data /var/www/html/unipanel
chmod -R 755 /var/www/html/unipanel
```

### SQLite Hatası
```bash
php -m | grep sqlite
# Eğer yoksa:
apt-get install php-sqlite3
systemctl restart apache2  # veya nginx
```

