# 🔍SHARK - Network Pentest

⚠️ **UYARI: Bu araç yalnızca eğitim ve akademik amaçlı geliştirilmiştir. Yalnızca kendi sahip olduğunuz veya izleme izniniz olan ağlarda kullanın. Yasalara uygun şekilde kullanım sorumluluğu kullanıcıya aittir.**

## 📋 Özellikler

### 🔧 Temel Özellikler
- ✅ **Aktif IP Tespiti**: Yerel ağdaki tüm aktif cihazları tespit eder
- 🔗 **MAC Adresi Eşleştirme**: IP adreslerini MAC adresleriyle eşleştirir
- 📱 **Cihaz Tanımlama**: MAC OUI lookup ile cihaz türünü tespit eder
- 🌐 **Ağ Trafiği İzleme**: DNS sorguları, HTTP/HTTPS trafiği analizi
- 💾 **PCAP Kaydetme**: Wireshark uyumlu paket yakalama
- 📊 **Detaylı Raporlama**: JSON formatında kapsamlı analiz raporu

### 🚀 Gelişmiş Özellikler
- 🔍 **Gelişmiş Cihaz Tanımlama**: OS fingerprinting, IoT cihaz tespiti, cihaz profilleme
- 🌐 **Ağ Topolojisi Analizi**: Cihaz bağlantıları, switch/router tespiti, topoloji görselleştirme
- 🔒 **Otomatik Penetrasyon Testi**: Güvenlik açığı tarama, zayıf kimlik bilgileri testi
- 🌍 **Web Aktivite İzleme**: Hangi sitelere gidildiği, arama sorguları, indirilen dosyalar
- 🎨 **Görselleştirme**: Ağ topolojisi haritaları, grafik raporlar
- 📈 **Kapsamlı Analiz**: Risk değerlendirmesi, güvenlik önerileri

### 🛠️ Modüler Yapı
- **Standalone Modüller**: Her özellik ayrı çalıştırılabilir
- **Dinamik Yükleme**: Sadece gerekli modüller yüklenir
- **Esnek Kullanım**: İhtiyaca göre özelleştirilebilir

## 🛠️ Kurulum

### Gereksinimler

- **Python 3.6+**
- **Root/Administrator yetkileri**
- **Linux/macOS** (Windows desteği sınırlı)

### Bağımlılık Kurulumu

```bash
# Temel Python kütüphaneleri
pip install scapy python-nmap requests

# Gelişmiş özellikler için (isteğe bağlı)
pip install networkx matplotlib paramiko psycopg2-binary pymssql

# Sistem seviyesi nmap kurulumu
# Ubuntu/Debian:
sudo apt-get install nmap

# CentOS/RHEL:
sudo yum install nmap

# macOS:
brew install nmap
```

### Hızlı Kurulum

```bash
# Otomatik kurulum scripti
chmod +x install.sh
./install.sh

# Windows için
install.bat
```

### Windows Kurulumu (Sınırlı Destek)

```bash
# Python kütüphaneleri
pip install scapy python-nmap requests

# Npcap kurulumu (WinPcap yerine)
# https://npcap.com/ adresinden indirin

# Nmap kurulumu
# https://nmap.org/download.html adresinden indirin
```

## 🚀 Kullanım

### 🔧 Ana Araç (shark.py)

#### Temel Kullanım
```bash
# Root yetkileriyle çalıştırın
sudo python3 shark.py --interface eth0 --duration 300 --output capture.pcap
```

#### Komut Satırı Seçenekleri
```bash
python3 shark.py [SEÇENEKLER]

Temel Seçenekler:
  -i, --interface INTERFACE    Ağ arayüzü (örn: eth0, wlan0)
  -a, --auto-interface         Otomatik ağ arayüzü tespit et
  -d, --duration DURATION      İzleme süresi (saniye, varsayılan: 300)
  -o, --output OUTPUT          Çıktı PCAP dosyası (varsayılan: network_capture.pcap)
  -v, --verbose                Detaylı çıktı
  -f, --fast                   Hızlı mod (sadece temel özellikler)

Gelişmiş Seçenekler:
  -A, --advanced               Gelişmiş özellikler (cihaz tanımlama, topoloji, penetrasyon)
  -t, --topology               Ağ topolojisi analizi
  -p, --penetration            Penetrasyon testleri
  -w, --web-activity           Web aktivite izleme
  -h, --help                   Yardım mesajını göster
```

#### Kullanım Örnekleri

```bash
# Temel izleme
sudo python3 shark.py --interface wlan0 --duration 300 --output wifi_analysis.pcap

# Otomatik ağ arayüzü tespit et
sudo python3 shark.py --auto-interface --duration 600

# Gelişmiş cihaz tanımlama
sudo python3 shark.py --interface eth0 --advanced --duration 300

# Ağ topolojisi analizi
sudo python3 shark.py --interface eth0 --topology --duration 600

# Penetrasyon testleri
sudo python3 shark.py --interface eth0 --penetration --duration 300

# Web aktivite izleme
sudo python3 shark.py --interface eth0 --web-activity --duration 600

# Tüm özellikler (kapsamlı analiz)
sudo python3 shark.py --auto-interface --advanced --topology --penetration --web-activity --duration 900

# Hızlı mod
sudo python3 shark.py --auto-interface --fast --duration 60
```

### 🛠️ Gerçek Zamanlı Modüller

#### 1. Gerçek Ağ Tarayıcı
```bash
# Gerçek ağ tarama
sudo python3 real_network_scanner.py --network 192.168.1.0/24

# Detaylı tarama
sudo python3 real_network_scanner.py --network 192.168.1.0/24 --verbose
```

#### 2. WiFi Ağ Tarayıcı
```bash
# WiFi ağları tara
sudo python3 wifi_network_scanner.py

# Detaylı WiFi analizi
sudo python3 wifi_network_scanner.py --verbose
```

#### 3. Gerçek Topoloji Analizi
```bash
# Gerçek topoloji çıkarma
sudo python3 real_topology_mapper.py --network 192.168.1.0/24

# Görselleştirme ile
sudo python3 real_topology_mapper.py --network 192.168.1.0/24 --verbose
```

#### 4. Gerçek Penetrasyon Testi
```bash
# Tek hedef penetrasyon testi
sudo python3 real_penetration_tester.py --target 192.168.1.1

# Ağ geneli penetrasyon testi
sudo python3 real_penetration_tester.py --target 192.168.1.0/24
```

#### 5. Gerçek Zamanlı Web Aktivite İzleme
```bash
# Gerçek web trafiği izleme
sudo python3 real_time_web_monitor.py --interface eth0 --duration 300

# Otomatik ağ arayüzü ile
sudo python3 real_time_web_monitor.py --auto-interface --duration 600
```

#### 6. Tüm Gerçek Modülleri Çalıştır
```bash
# Kapsamlı gerçek analiz
sudo python3 run_real_analysis.py --network 192.168.1.0/24 --duration 300

# Bazı modülleri atla
sudo python3 run_real_analysis.py --network 192.168.1.0/24 --skip-modules web
```

### 🎭 Ağ Simülatörü

#### 1. Statik Simülasyon (Demo)
```bash
# Hızlı test (10 cihaz, 5 dakika) - sadece log
python3 run_network_simulator.py --quick

# Gerçek ağı analiz et ve simüle et - sadece log
python3 run_network_simulator.py --analyze-real 192.168.1.0/24
```

#### 2. Gerçek Paket Simülasyonu ⚠️
```bash
# Hızlı gerçek simülasyon (10 cihaz, 5 dakika) - GERÇEK PAKETLER
sudo python3 run_real_simulator.py --quick

# Gerçek ağı analiz et ve gerçek paketlerle simüle et
sudo python3 run_real_simulator.py --analyze-real 192.168.1.0/24

# Özel gerçek simülasyon - GERÇEK PAKETLER
sudo python3 run_real_simulator.py --custom --devices 50 --duration 1800

# Saldırı simülasyonu dahil - GERÇEK PAKETLER
sudo python3 run_real_simulator.py --attack-simulation --devices 30
```

#### 3. Gelişmiş Simülasyon
```bash
# Statik simülasyon (konfigürasyon dosyası ile)
python3 network_simulator.py --config simulation_config.json

# Gerçek paket simülasyonu (konfigürasyon dosyası ile)
sudo python3 real_network_simulator.py --config simulation_config.json
```

### 🧪 Test ve Debug

```bash
# Tüm modüllerin çalışıp çalışmadığını test et
python3 debug_shark.py
```

## 📊 Çıktı Formatları

### 📁 Dosya Türleri

#### 1. PCAP Dosyaları
- **Ana PCAP**: `network_capture.pcap` - Wireshark ile açılabilir
- **Tüm yakalanan paketler**: Tam ağ trafiği analizi

#### 2. JSON Raporları
- **Temel Rapor**: `*_report.json` - Cihaz bilgileri ve trafik özeti
- **Gerçek Ağ Tarama**: `real_network_scan.json` - Gerçek cihaz profilleri
- **Gerçek Topoloji**: `real_topology.json` - Gerçek ağ yapısı
- **Gerçek Web Aktivite**: `real_web_activity.json` - Gerçek web trafiği
- **Birleşik Rapor**: `real_analysis_report.json` - Tüm gerçek analizler

#### 3. Görsel Dosyalar
- **Topoloji Haritası**: `*_topology.png` - Ağ yapısı görselleştirmesi

### 📄 Örnek Rapor İçerikleri

#### Temel Ağ Raporu
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "interface": "eth0",
  "active_devices": [
    {
      "ip": "192.168.1.100",
      "mac": "00:1b:21:xx:xx:xx",
      "device_type": "Apple",
      "traffic_stats": {
        "packets_sent": 150,
        "tcp_packets": 120,
        "dns_queries": ["google.com", "github.com"]
      }
    }
  ],
  "traffic_summary": {
    "total_devices": 5,
    "total_packets": 1250
  }
}
```

#### Gerçek Cihaz Profili
```json
{
  "device_id": "192.168.1.100",
  "mac_address": "00:11:22:33:44:55",
  "vendor": "Dell Inc.",
  "device_type": "computer",
  "os_fingerprint": {
    "os": "Windows 10",
    "version": "10.0.19041",
    "confidence": 95
  },
  "open_ports": [
    {"port": 22, "service": "ssh", "version": "OpenSSH 8.2"},
    {"port": 80, "service": "http", "version": "Apache 2.4.41"}
  ],
  "scan_timestamp": "2024-01-15T10:30:00Z",
  "scan_duration": 45.2
}
```

#### Gerçek Web Aktivite Raporu
```json
{
  "user_192.168.1.100": {
    "dns_queries": [
      {
        "domain": "google.com",
        "timestamp": "2024-01-15T10:30:00Z",
        "response_time": 0.045
      }
    ],
    "http_requests": [
      {
        "host": "google.com",
        "path": "/search?q=python",
        "user_agent": "Mozilla/5.0...",
        "timestamp": "2024-01-15T10:30:15Z",
        "response_code": 200
      }
    ],
    "https_connections": [
      {
        "host": "github.com",
        "sni": "github.com",
        "timestamp": "2024-01-15T10:31:00Z",
        "cipher_suite": "TLS_AES_256_GCM_SHA384"
      }
    ],
    "search_queries": ["python programming", "machine learning"],
    "downloaded_files": ["document.pdf", "image.jpg"],
    "total_bytes": 2048576
  }
}
```

### 🖥️ Konsol Çıktısı
```
🔍 AĞ İZLEME RAPORU
============================================================
📡 Ağ Arayüzü: eth0
🌐 Aktif Cihazlar: 5
📦 Yakalanan Paketler: 1250
💾 PCAP Dosyası: network_capture.pcap

📱 TESPİT EDİLEN CİHAZLAR:
----------------------------------------
🔗 192.168.1.1     | 00:1b:21:xx:xx:xx | Apple
🔗 192.168.1.100   | 08:00:27:xx:xx:xx | VirtualBox
🔗 192.168.1.101   | 52:54:00:xx:xx:xx | QEMU

🌐 WEB AKTİVİTE RAPORU
============================================================
👥 Toplam Kullanıcı: 3
📊 Toplam Aktivite: 45
🔍 DNS Sorguları: 23
🌍 HTTP İstekleri: 15
🔎 Arama Sorguları: 7

👤 KULLANICI AKTİVİTELERİ:
----------------------------------------
🔗 192.168.1.100:
   ⏱️  Session Süresi: 1800 saniye
   📊 Toplam Aktivite: 20
   🌐 Benzersiz Domain: 12
   🏆 En Çok Ziyaret Edilen:
      • google.com: 8 kez
      • github.com: 5 kez
   🔎 Son Arama Sorguları:
      • "python programming"
      • "machine learning tutorial"
```

## 🔒 Güvenlik ve Etik Kullanım

### ⚠️ Önemli Uyarılar

1. **Yasal Kullanım**: Bu araç yalnızca kendi sahip olduğunuz ağlarda kullanın
2. **İzin Gereksinimi**: İzleme izniniz olmayan ağlarda kullanmayın
3. **Eğitim Amaçlı**: Sadece akademik ve eğitim amaçlı kullanım
4. **HTTPS Sınırlaması**: HTTPS trafiği şifreli olduğu için sadece meta veriler görülebilir

### 🛡️ Güvenli Test Ortamı

```bash
# Kendi test ağınızı oluşturun
# VirtualBox/VMware ile izole ortam
# Docker container'lar ile test
# Kendi WiFi ağınızda test
```

## 🔧 Teknik Detaylar

### 📡 Desteklenen Protokoller

- **TCP**: Bağlantı analizi ve port tespiti
- **UDP**: DNS sorguları ve diğer UDP trafiği
- **ICMP**: Ping ve ağ tanılama
- **DNS**: Domain sorguları ve çözümleme
- **HTTP**: Şifrelenmemiş web trafiği
- **HTTPS**: Meta veri analizi (içerik şifreli)
- **ARP**: MAC adresi çözümleme
- **SNMP**: Ağ cihaz yönetimi (isteğe bağlı)

### 🔍 Cihaz Tanımlama

- **MAC OUI Database**: Genişletilmiş yerleşik veritabanı
- **Online Lookup**: MAC Vendors API entegrasyonu
- **Nmap OS Detection**: İşletim sistemi tespiti
- **IoT Cihaz Tespiti**: Özel protokoller ve portlar
- **Vendor Profilleme**: Cihaz kategorileri ve risk analizi

### 🚀 Gelişmiş Özellikler

#### Ağ Topolojisi
- **Graph Analizi**: NetworkX ile ağ yapısı analizi
- **Merkezilik Ölçüleri**: Degree, betweenness, closeness centrality
- **Switch/Router Tespiti**: SNMP ve port analizi
- **VLAN Keşfi**: Sanal ağ segmentasyonu

#### Penetrasyon Testi
- **Port Tarama**: Nmap entegrasyonu
- **Güvenlik Açığı Tespiti**: Yaygın zafiyetler
- **Kimlik Bilgisi Testi**: Zayıf şifreler
- **SSL/TLS Analizi**: Şifreleme güvenliği

#### Web Aktivite İzleme
- **DNS Analizi**: Domain sorguları
- **HTTP/HTTPS Trafiği**: Web aktiviteleri
- **Arama Sorguları**: Arama motoru analizi
- **Dosya İndirme**: İndirilen dosya tespiti

### ⚡ Performans Optimizasyonu

- **Threading**: Asenkron paket yakalama
- **Memory Management**: Büyük dosyalar için optimize edilmiş
- **Filtering**: Gereksiz paket filtreleme
- **Lazy Loading**: Modüller sadece gerektiğinde yüklenir
- **Caching**: Tekrarlayan işlemler için önbellekleme

## 🐛 Sorun Giderme

### Yaygın Hatalar

```bash
# Yetki hatası
❌ Bu araç root yetkileri gerektirir!
Çözüm: sudo python3 shark.py

# Ağ arayüzü bulunamadı
❌ Ağ arayüzü belirtilmedi
Çözüm: --auto-interface veya --interface eth0 kullanın

# Kütüphane eksik
❌ Gerekli kütüphane eksik: scapy
Çözüm: pip install scapy python-nmap requests

# Gelişmiş modül hatası
❌ AdvancedDeviceDetector bulunamadı
Çözüm: pip install networkx matplotlib

# Nmap bulunamadı
❌ Nmap sistem seviyesinde kurulu değil
Çözüm: sudo apt-get install nmap (Ubuntu/Debian)
```

### 🧪 Test ve Debug

```bash
# Tüm modüllerin durumunu kontrol et
python3 debug_shark.py

# Web aktivite modülünü test et
python3 test_web_activity.py

# Sadece temel özelliklerle çalıştır
python3 shark.py --fast --auto-interface --duration 60
```

### 📋 Log Dosyaları

```bash
# Detaylı loglar
tail -f network_monitor.log

# Hata ayıklama
python3 shark.py --verbose

# Modül bazlı test
python3 run_advanced_device_detection.py --target 127.0.0.1 --verbose
```

### 🔧 Performans Sorunları

```bash
# Büyük ağlar için hızlı mod
python3 shark.py --fast --auto-interface --duration 300

# Sadece belirli modülleri çalıştır
python3 run_all_modules.py --target 192.168.1.1 --skip-modules web

# Memory kullanımını azalt
python3 shark.py --auto-interface --duration 120 --output small_capture.pcap
```

## 📚 Eğitim Kaynakları

### 🎓 Ağ Güvenliği Kavramları

- **Packet Analysis**: Scapy dokümantasyonu ve kullanımı
- **Network Monitoring**: Wireshark ile paket analizi
- **Ethical Hacking**: Sertifikalı etik hacker eğitimi
- **Network Forensics**: Ağ adli bilişim teknikleri
- **Penetration Testing**: Güvenlik açığı değerlendirmesi
- **Network Topology**: Ağ yapısı analizi ve görselleştirme

### 🛠️ İlgili Araçlar

#### Paket Analizi
- **Wireshark**: Gelişmiş paket analizi ve görselleştirme
- **tcpdump**: Komut satırı paket yakalama
- **tshark**: Wireshark komut satırı arayüzü

#### Ağ Keşif
- **Nmap**: Ağ keşif ve güvenlik tarama
- **Masscan**: Hızlı port tarama
- **Zmap**: Internet ölçeğinde tarama

#### Ağ Yönetimi
- **Netstat**: Ağ bağlantı durumu
- **ss**: Modern socket istatistikleri
- **iftop**: Ağ trafiği izleme
- **nethogs**: Process bazlı ağ kullanımı

#### Güvenlik Testi
- **Metasploit**: Penetrasyon testi framework'ü
- **Burp Suite**: Web uygulama güvenlik testi
- **OWASP ZAP**: Web güvenlik tarayıcısı
- **Nikto**: Web sunucu güvenlik tarayıcısı

### 📖 Öğrenme Yol Haritası

#### Başlangıç Seviyesi
1. **Temel Ağ Kavramları**: IP, TCP, UDP, DNS
2. **Shark Temel Kullanım**: Basit ağ izleme
3. **Wireshark**: Paket analizi temelleri

#### Orta Seviye
1. **Gelişmiş Ağ Protokolleri**: HTTP, HTTPS, SNMP
2. **Shark Gelişmiş Özellikler**: Cihaz tanımlama, topoloji
3. **Güvenlik Testleri**: Penetrasyon testi temelleri

#### İleri Seviye
1. **Ağ Güvenliği**: Firewall, IDS/IPS, VPN
2. **Shark Tam Analiz**: Tüm modüllerle kapsamlı analiz
3. **Özel Senaryolar**: IoT güvenliği, ağ adli bilişim

## 📁 Proje Yapısı

```
Shark/
├── shark.py                          # Ana ağ izleme aracı
├── real_network_scanner.py           # Gerçek ağ tarama aracı
├── real_time_web_monitor.py          # Gerçek zamanlı web izleme
├── real_topology_mapper.py           # Gerçek topoloji analizi
├── real_penetration_tester.py        # Gerçek penetrasyon testi
├── wifi_network_scanner.py           # WiFi ağ tarayıcı
├── run_real_analysis.py              # Tüm gerçek modülleri çalıştır
├── real_network_simulator.py         # Gerçek paket simülatörü ⚠️
├── run_real_simulator.py             # Gerçek simülatör çalıştırıcı ⚠️
├── debug_shark.py                    # Debug ve test scripti
├── requirements.txt                  # Python bağımlılıkları
├── install.sh                        # Linux/macOS kurulum scripti
├── install.bat                       # Windows kurulum scripti
├── README.md                         # Bu dosya
├── USAGE_EXAMPLES.md                 # Detaylı kullanım örnekleri
└── network_monitor.log               # Log dosyası
```

## 📄 Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Ticari kullanım yasaktır.

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

### 🎯 Katkı Alanları

- **Yeni Modüller**: Ek ağ analiz özellikleri
- **Güvenlik İyileştirmeleri**: Yeni güvenlik testleri
- **Performans Optimizasyonu**: Hız ve bellek iyileştirmeleri
- **Dokümantasyon**: Kullanım kılavuzları ve örnekler
- **Test Coverage**: Unit testler ve entegrasyon testleri

## 📞 İletişim

- **Eğitim Amaçlı**: Bu araç sadece eğitim ve akademik araştırma için
- **Güvenlik**: Güvenlik açığı bildirimi için lütfen sorumlu açıklama yapın
- **Destek**: GitHub Issues üzerinden destek alın
- **Öneriler**: Yeni özellik önerileri için GitHub Discussions kullanın

## 🏆 Özellikler Özeti

### ✅ Mevcut Özellikler
- ✅ Temel ağ izleme ve paket yakalama
- ✅ Gelişmiş cihaz tanımlama ve profilleme
- ✅ Ağ topolojisi analizi ve görselleştirme
- ✅ Otomatik penetrasyon testi
- ✅ Web aktivite izleme ve analizi
- ✅ Modüler yapı ve standalone çalıştırma
- ✅ Kapsamlı raporlama ve görselleştirme

### 🚀 Gelecek Özellikler
- 🔄 Gerçek zamanlı ağ izleme dashboard'u
- 🔄 Machine learning tabanlı anomali tespiti
- 🔄 Cloud entegrasyonu ve uzaktan izleme
- 🔄 API arayüzü ve REST endpoints
- 🔄 Docker containerization
- 🔄 Web tabanlı kullanıcı arayüzü

---

⚠️ **SON UYARI**: Bu araç güçlü bir ağ izleme aracıdır. Sorumlu ve etik bir şekilde kullanın. Yasalara uygun olmayan kullanım sorumluluğu kullanıcıya aittir.

**🎓 Eğitim Amaçlı**: Bu araç sadece ağ güvenliği eğitimi, akademik araştırma ve kendi ağlarınızın güvenlik testleri için tasarlanmıştır.


