#!/usr/bin/expect -f

# Support.php dosyasını sunucuya yükleme scripti (expect kullanarak)
# Kullanım: ./upload_support_expect.sh

set timeout 30
set server "root@89.252.152.125"
set password "651CceSl"
set local_file "marketing/support.php"
set remote_path "/var/www/html/unipanel/marketing/support.php"

spawn scp $local_file $server:$remote_path

expect {
    "password:" {
        send "$password\r"
        exp_continue
    }
    "yes/no" {
        send "yes\r"
        exp_continue
    }
    eof
}

wait

if {[catch {exec test -f $local_file}] == 0} {
    puts "✅ Dosya başarıyla yüklendi!"
    puts "🌐 Test URL: https://foursoftware.com.tr/unipanel/marketing/support.php"
} else {
    puts "❌ Hata: Dosya yüklenemedi!"
    exit 1
}





