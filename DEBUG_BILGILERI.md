# Debug Bilgileri - Nereden Bakılır?

## 🔍 Debug Bilgilerini Kontrol Etme Yöntemleri

### 1. **Backend PHP Error Log'ları**

**Dosya Yolu:**
```
/Applications/XAMPP/xamppfiles/logs/php_error_log
```

**Terminal'de Kontrol:**
```bash
# Son 50 satırı göster
tail -50 /Applications/XAMPP/xamppfiles/logs/php_error_log

# Canlı takip (yeni log'lar geldikçe gösterir)
tail -f /Applications/XAMPP/xamppfiles/logs/php_error_log

# Sadece Register Step API log'larını göster
tail -100 /Applications/XAMPP/xamppfiles/logs/php_error_log | grep "Register Step API"
```

**XAMPP Control Panel'den:**
- XAMPP Control Panel'i aç
- "Logs" butonuna tıkla
- "PHP Error Log" seçeneğini seç

---

### 2. **Swift Debug Log'ları**

**Xcode Console:**
- Xcode'da uygulamayı çalıştır
- Alt paneldeki "Console" sekmesine bak
- Kayıt işlemi sırasında şu log'lar görünecek:
  - `📧 Step 1: E-posta doğrulama kodu gönderiliyor`
  - `📦 Step1 Request Body: {...}`
  - `❌ API hatası: ...`

**Debug Log Dosyası:**
```
/Applications/XAMPP/xamppfiles/htdocs/unipanel/.cursor/debug.log
```

**Terminal'de Kontrol:**
```bash
# Son log'ları göster
tail -20 /Applications/XAMPP/xamppfiles/htdocs/unipanel/.cursor/debug.log

# Canlı takip
tail -f /Applications/XAMPP/xamppfiles/htdocs/unipanel/.cursor/debug.log
```

---

### 3. **Backend API Response'u**

**Hata Mesajında Debug Bilgisi:**
Backend kodunu güncelledim, artık hata mesajında debug bilgisi görünmeli:
- Alınan step değeri (raw)
- Step değerinin tipi
- Normalize edilmiş step değeri

**Örnek Hata Mesajı:**
```json
{
    "success": false,
    "error": "Geçersiz adım. Step değeri 1, 2, 3 veya 4 olmalıdır. Alınan değer: 1 (tip: integer), normalize edilmiş: 1"
}
```

**Terminal'de Test:**
```bash
curl -X POST https://foursoftware.com.tr/unipanel/api/auth_register_step.php \
  -H "Content-Type: application/json" \
  -d '{"step":1,"email":"test@example.com"}'
```

---

### 4. **Xcode Console'da Debug Bilgileri**

**Xcode'da:**
1. Uygulamayı çalıştır (⌘R)
2. Alt paneldeki "Console" sekmesine bak
3. Kayıt işlemi sırasında şu log'lar görünecek:
   - `📧 Step 1: E-posta doğrulama kodu gönderiliyor: ...`
   - `📦 Step1 Request Body: {"step":1,"email":"..."}`
   - `❌ API hatası: ...` (hata varsa)

**Filter:**
- Console'da "Register" veya "Step" yazarak filtreleyebilirsin

---

## 🐛 Şu Anda Görünen Sorun

**Hata Mesajı:**
```
"error": "Geçersiz adım."
```

**Beklenen:**
```
"error": "Geçersiz adım. Step değeri 1, 2, 3 veya 4 olmalıdır. Alınan değer: 1 (tip: integer), normalize edilmiş: 1"
```

**Sorun:**
Backend'in eski kodunu kullanıyor olabilir veya PHP opcache sorunu var.

**Çözüm:**
1. PHP opcache'i temizle
2. Backend kodunu kontrol et
3. Error log'larını kontrol et

---

## 📝 Hızlı Kontrol Komutları

```bash
# PHP error log'unu kontrol et
tail -50 /Applications/XAMPP/xamppfiles/logs/php_error_log | grep "Register Step"

# Swift debug log'unu kontrol et
tail -20 /Applications/XAMPP/xamppfiles/htdocs/unipanel/.cursor/debug.log

# Backend API'yi test et
curl -X POST https://foursoftware.com.tr/unipanel/api/auth_register_step.php \
  -H "Content-Type: application/json" \
  -d '{"step":1,"email":"test@example.com"}'
```
