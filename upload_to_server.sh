#!/bin/bash
# SSH ile sunucuya bağlanıp git pull yap

HOST="89.252.152.125"
USER="root"
PASSWORD="651CceSl"
REMOTE_PATH="/var/www/html/unipanel"

# Farklı olası yolları dene
PATHS=(
    "/var/www/html/unipanel"
    "/var/www/unipanel"
    "/home/unipanel"
    "/opt/unipanel"
    "/usr/share/nginx/html/unipanel"
    "/srv/www/unipanel"
)

echo "Sunucuya bağlanılıyor..."

for path in "${PATHS[@]}"; do
    echo "Deneniyor: $path"
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$USER@$HOST" "cd $path && pwd && git pull" 2>&1 && {
        echo "✅ Başarılı! Path: $path"
        exit 0
    }
done

echo "❌ Hiçbir path'te git pull yapılamadı"
exit 1
