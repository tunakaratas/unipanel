<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Destek - UniFour</title>
    <meta name="description" content="UniFour destek sayfası. Yardıma mı ihtiyacınız var? Bizimle iletişime geçin veya sık sorulan sorulara göz atın.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="styles.css">
    <style>
        .support-page {
            max-width: 1000px;
            margin: 0 auto;
            padding: 8rem 2rem 4rem;
            line-height: 1.8;
            color: #334155;
        }
        
        .support-header {
            text-align: center;
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 2px solid #e2e8f0;
        }
        
        .support-header h1 {
            font-size: 2.5rem;
            font-weight: 800;
            color: #0f172a;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .support-header p {
            color: #64748b;
            font-size: 1.1rem;
        }
        
        .support-content {
            background: white;
            padding: 3rem;
            border-radius: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        .contact-section {
            background: linear-gradient(135deg, #eef2ff 0%, #f8fafc 100%);
            border-left: 4px solid #6366f1;
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 3rem;
        }
        
        .contact-section h2 {
            font-size: 1.5rem;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .contact-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        
        .contact-card {
            background: white;
            padding: 1.5rem;
            border-radius: 0.75rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .contact-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        
        .contact-card a {
            text-decoration: none;
            color: inherit;
            display: block;
        }
        
        .contact-card-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .contact-card-icon.email {
            background: linear-gradient(135deg, #ec4899 0%, #f43f5e 100%);
            color: white;
        }
        
        .contact-card-icon.website {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
            color: white;
        }
        
        .contact-card h3 {
            font-size: 1.1rem;
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 0.5rem;
        }
        
        .contact-card p {
            font-size: 0.9rem;
            color: #64748b;
            margin: 0;
        }
        
        .faq-section {
            margin-top: 3rem;
        }
        
        .faq-section h2 {
            font-size: 1.5rem;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .faq-item {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 0.75rem;
            margin-bottom: 1rem;
            overflow: hidden;
            transition: all 0.3s;
        }
        
        .faq-item.active {
            border-color: #6366f1;
            box-shadow: 0 2px 8px rgba(99, 102, 241, 0.1);
        }
        
        .faq-question {
            padding: 1.25rem 1.5rem;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            color: #0f172a;
            transition: background 0.2s;
        }
        
        .faq-question:hover {
            background: #f1f5f9;
        }
        
        .faq-question i {
            color: #6366f1;
            transition: transform 0.3s;
        }
        
        .faq-item.active .faq-question i {
            transform: rotate(180deg);
        }
        
        .faq-answer {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out, padding 0.3s;
            padding: 0 1.5rem;
        }
        
        .faq-item.active .faq-answer {
            max-height: 500px;
            padding: 0 1.5rem 1.25rem 1.5rem;
        }
        
        .faq-answer p {
            color: #475569;
            margin: 0;
            line-height: 1.7;
        }
        
        .back-link {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: #6366f1;
            text-decoration: none;
            font-weight: 600;
            margin-bottom: 2rem;
            transition: color 0.2s;
        }
        
        .back-link:hover {
            color: #4f46e5;
        }
        
        .app-info {
            background: #f8fafc;
            padding: 1.5rem;
            border-radius: 0.75rem;
            margin-top: 2rem;
            text-align: center;
        }
        
        .app-info p {
            margin: 0.5rem 0;
            color: #64748b;
        }
        
        @media (max-width: 768px) {
            .support-page {
                padding: 6rem 1rem 2rem;
            }
            
            .support-content {
                padding: 2rem 1.5rem;
            }
            
            .support-header h1 {
                font-size: 2rem;
            }
            
            .contact-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="support-page">
        <a href="index.html" class="back-link">
            <i class="fas fa-arrow-left"></i>
            Ana Sayfaya Dön
        </a>
        
        <div class="support-header">
            <h1><i class="fas fa-question-circle"></i> Destek</h1>
            <p>Yardıma mı ihtiyacınız var? Size yardımcı olmak için buradayız!</p>
        </div>
        
        <div class="support-content">
            <!-- İletişim Bölümü -->
            <div class="contact-section">
                <h2>
                    <i class="fas fa-envelope"></i>
                    İletişim
                </h2>
                <p style="color: #64748b; margin-bottom: 1.5rem;">
                    Sorularınız, önerileriniz veya destek talepleriniz için bizimle iletişime geçebilirsiniz.
                </p>
                
                <div class="contact-grid">
                    <div class="contact-card">
                        <a href="mailto:support@foursoftware.com.tr">
                            <div class="contact-card-icon email">
                                <i class="fas fa-envelope"></i>
                            </div>
                            <h3>E-posta</h3>
                            <p>support@foursoftware.com.tr</p>
                        </a>
                    </div>
                    
                    <div class="contact-card">
                        <a href="https://foursoftware.com.tr" target="_blank" rel="noopener noreferrer">
                            <div class="contact-card-icon website">
                                <i class="fas fa-globe"></i>
                            </div>
                            <h3>Web Sitesi</h3>
                            <p>foursoftware.com.tr <i class="fas fa-external-link-alt" style="font-size: 0.75rem; margin-left: 0.25rem;"></i></p>
                        </a>
                    </div>
                </div>
            </div>
            
            <!-- SSS Bölümü -->
            <div class="faq-section">
                <h2>
                    <i class="fas fa-question-circle"></i>
                    Sık Sorulan Sorular
                </h2>
                
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Hesabımı nasıl silebilirim?</span>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="faq-answer">
                        <p>Mobil uygulamada Ayarlar > Hesabı Sil bölümünden hesabınızı silebilirsiniz. Bu işlem geri alınamaz ve tüm verileriniz kalıcı olarak silinir.</p>
                    </div>
                </div>
                
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Bildirimleri nasıl açabilirim?</span>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="faq-answer">
                        <p>Mobil uygulamada Ayarlar > Bildirimler bölümünden bildirim izinlerini yönetebilirsiniz. Ayrıca iOS ayarlarından da bildirim izinlerini kontrol edebilirsiniz.</p>
                    </div>
                </div>
                
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>QR kod nasıl taranır?</span>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="faq-answer">
                        <p>Mobil uygulamada Topluluklar sekmesindeki QR kod butonuna tıklayarak QR kod tarayıcısını açabilirsiniz. Kamera izni vermeniz gerekecektir.</p>
                    </div>
                </div>
                
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Web sitesine nasıl erişebilirim?</span>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="faq-answer">
                        <p>Yukarıdaki "Web Sitesi" kartına tıklayarak veya tarayıcınızda <strong>foursoftware.com.tr</strong> adresine giderek web sitemize erişebilirsiniz.</p>
                    </div>
                </div>
                
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Topluluk nasıl oluşturulur?</span>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="faq-answer">
                        <p>Web sitemizden kayıt olarak topluluk oluşturabilirsiniz. Kayıt işlemi sırasında topluluk bilgilerinizi girmeniz gerekecektir.</p>
                    </div>
                </div>
                
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Etkinlik nasıl oluşturulur?</span>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="faq-answer">
                        <p>Topluluk yöneticisi olarak giriş yaptıktan sonra, Etkinlikler bölümünden yeni etkinlik oluşturabilirsiniz. Etkinlik detaylarını, tarih, saat ve konum bilgilerini ekleyebilirsiniz.</p>
                    </div>
                </div>
                
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Ürün nasıl satılır?</span>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                    <div class="faq-answer">
                        <p>Topluluk yöneticisi olarak Market bölümünden ürün ekleyebilir, fiyat belirleyebilir ve stok yönetimi yapabilirsiniz. Üyeler ürünleri sepete ekleyip satın alabilir.</p>
                    </div>
                </div>
            </div>
            
            <!-- Uygulama Bilgisi -->
            <div class="app-info">
                <p><strong>UniFour</strong> - Üniversite Toplulukları Platformu</p>
                <p style="font-size: 0.875rem;">Four Software tarafından geliştirilmiştir</p>
                <p style="font-size: 0.875rem; color: #94a3b8;">© 2025 Tüm hakları saklıdır.</p>
            </div>
        </div>
    </div>
    
    <script>
        function toggleFaq(element) {
            const faqItem = element.parentElement;
            const isActive = faqItem.classList.contains('active');
            
            // Tüm FAQ öğelerini kapat
            document.querySelectorAll('.faq-item').forEach(item => {
                item.classList.remove('active');
            });
            
            // Tıklanan öğeyi aç/kapat
            if (!isActive) {
                faqItem.classList.add('active');
            }
        }
    </script>
</body>
</html>





