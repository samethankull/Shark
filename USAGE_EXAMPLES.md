# 🔍 Etik Ağ İzleme Aracı - Kullanım Örnekleri

⚠️ **UYARI: Bu araç yalnızca eğitim ve akademik amaçlı geliştirilmiştir. Yalnızca kendi sahip olduğunuz veya izleme izniniz olan ağlarda kullanın.**

## 📋 İçindekiler

1. [Hızlı Başlangıç](#hızlı-başlangıç)
2. [Temel Kullanım Örnekleri](#temel-kullanım-örnekleri)
3. [Gelişmiş Kullanım Senaryoları](#gelişmiş-kullanım-senaryoları)
4. [Ağ Türlerine Göre Kullanım](#ağ-türlerine-göre-kullanım)
5. [Sorun Giderme Örnekleri](#sorun-giderme-örnekleri)
6. [Analiz ve Raporlama](#analiz-ve-raporlama)

## 🚀 Hızlı Başlangıç

### İlk Kurulum ve Test

```bash
# 1. Kurulum
chmod +x install.sh
./install.sh

# 2. Basit test (30 saniye)
sudo python3 shark.py --auto-interface --duration 30

# 3. Sonuçları kontrol et
ls -la *.pcap *.json
```

### Temel Komut Yapısı

```bash
sudo python3 shark.py [SEÇENEKLER]

Temel Seçenekler:
  -i, --interface     Ağ arayüzü belirt
  -a, --auto-interface  Otomatik ağ arayüzü tespit et
  -d, --duration      İzleme süresi (saniye)
  -o, --output        Çıktı dosyası adı
  -v, --verbose       Detaylı çıktı
```

## 📖 Temel Kullanım Örnekleri

### 1. Otomatik Ağ Tespiti ile Hızlı İzleme

```bash
# 5 dakika otomatik izleme
sudo python3 shark.py --auto-interface --duration 300

# Çıktı:
# 🔍 Otomatik ağ arayüzü: eth0
# 🌐 Ağ: 192.168.1.0/24
# ✅ 5 aktif IP bulundu
# 🚀 300 saniye boyunca izleme başlatılıyor...
```

### 2. Belirli Ağ Arayüzü ile İzleme

```bash
# Ethernet arayüzü
sudo python3 shark.py --interface eth0 --duration 180

# WiFi arayüzü
sudo python3 shark.py --interface wlan0 --duration 300

# USB Ethernet adaptörü
sudo python3 shark.py --interface enp0s3 --duration 120
```

### 3. Özel Çıktı Dosyası ile İzleme

```bash
# Özel dosya adı
sudo python3 shark.py --interface eth0 --output my_network_analysis.pcap

# Tarihli dosya adı
sudo python3 shark.py --interface wlan0 --output "wifi_$(date +%Y%m%d_%H%M%S).pcap"

# Klasör belirtme
sudo python3 shark.py --interface eth0 --output /tmp/network_capture.pcap
```

### 4. Detaylı Çıktı ile İzleme

```bash
# Verbose mod ile detaylı loglar
sudo python3 shark.py --interface eth0 --duration 300 --verbose

# Çıktı örneği:
# 🌐 DNS Sorgusu: 192.168.1.100 -> google.com
# 🔒 HTTPS: 192.168.1.100 -> 142.250.191.14:443
# 🌍 HTTP: 192.168.1.101 -> example.com
```

### 5. Gelişmiş Özellikler ile İzleme

```bash
# Gelişmiş cihaz tanımlama ve topoloji analizi
sudo python3 shark.py --interface eth0 --duration 300 --advanced

# Sadece ağ topolojisi analizi
sudo python3 shark.py --interface eth0 --duration 300 --topology

# Sadece penetrasyon testleri
sudo python3 shark.py --interface eth0 --duration 300 --penetration

# Tüm gelişmiş özellikler
sudo python3 shark.py --interface eth0 --duration 600 --advanced --verbose

# Sadece web aktivite izleme
sudo python3 shark.py --interface eth0 --duration 300 --web-activity
```

## 🔧 Gelişmiş Kullanım Senaryoları

### 1. Gelişmiş Cihaz Tanımlama

```bash
# OS fingerprinting ve cihaz profilleme
sudo python3 shark.py --interface eth0 --duration 300 --advanced

# Çıktı örneği:
# 📱 192.168.1.100: Apple - computer (Risk: Low)
# 📱 192.168.1.101: Samsung - mobile (Risk: Medium)
# 📱 192.168.1.102: Philips Hue - iot (Risk: High)
# 📊 Toplam 5 cihaz, 2 IoT cihaz, 1 yüksek riskli cihaz
```

### 2. Ağ Topolojisi Analizi

```bash
# Ağ topolojisi haritalama
sudo python3 shark.py --interface eth0 --duration 300 --topology

# Çıktı dosyaları:
# - network_capture_topology.png (görsel harita)
# - network_capture_topology_data.json (ham veri)
# - network_capture_topology_report.json (analiz raporu)

# Çıktı örneği:
# 🌐 Topoloji Analizi:
#    📊 Toplam cihaz: 8
#    🔗 Toplam bağlantı: 15
#    🏥 Ağ sağlığı: Good
```

### 3. Penetrasyon Testleri

```bash
# Güvenlik açığı tarama
sudo python3 shark.py --interface eth0 --duration 300 --penetration

# Çıktı dosyaları:
# - network_capture_penetration_192_168_1_100.json
# - network_capture_combined_penetration_report.json

# Çıktı örneği:
# 🔒 Penetrasyon Testleri:
#    🎯 192.168.1.100: Risk Skoru 45 - 3 güvenlik açığı
#    🎯 192.168.1.101: Risk Skoru 75 - 7 güvenlik açığı
```

### 4. Web Aktivite İzleme

```bash
# Web aktivite analizi
sudo python3 shark.py --interface eth0 --duration 300 --web-activity

# Çıktı dosyaları:
# - network_capture_web_activity_report.json

# Çıktı örneği:
# 🌐 WEB AKTİVİTE RAPORU
# ============================================================
# 👥 Toplam Kullanıcı: 3
# 📊 Toplam Aktivite: 156
# 🔍 DNS Sorguları: 89
# 🌍 HTTP İstekleri: 45
# 🔒 HTTPS Bağlantıları: 22
# 🔎 Arama Sorguları: 8
# 📥 İndirilen Dosyalar: 3
# 
# 👤 KULLANICI AKTİVİTELERİ:
# ----------------------------------------
# 🔗 192.168.1.100:
#    ⏱️  Session Süresi: 1800 saniye
#    📊 Toplam Aktivite: 67
#    🌐 Benzersiz Domain: 23
#    🏆 En Çok Ziyaret Edilen:
#       • google.com: 15 kez
#       • youtube.com: 12 kez
#       • facebook.com: 8 kez
#    📂 Kategoriler:
#       • social_media: 12
#       • entertainment: 18
#       • work: 8
#    🔎 Son Arama Sorguları:
#       • "python programlama"
#       • "ağ güvenliği"
#       • "linux komutları"
#    📥 Son İndirilen Dosyalar:
#       • document.pdf
#       • image.jpg
#    🌐 Kullanılan Tarayıcılar:
#       • Chrome 96.0: 45 kez
#       • Firefox 95.0: 22 kez
```

### 4. Uzun Süreli İzleme

```bash
# 1 saat izleme
sudo python3 shark.py --interface eth0 --duration 3600 --output long_term_capture.pcap

# Arka planda çalıştırma
nohup sudo python3 shark.py --interface eth0 --duration 7200 --output background_capture.pcap &

# Süreç kontrolü
ps aux | grep shark.py
```

### 2. Periyodik İzleme

```bash
# Her 10 dakikada bir 2 dakika izleme
while true; do
    sudo python3 shark.py --interface eth0 --duration 120 --output "capture_$(date +%H%M).pcap"
    sleep 600
done
```

### 3. Çoklu Ağ Arayüzü İzleme

```bash
# Ethernet ve WiFi aynı anda
sudo python3 shark.py --interface eth0 --duration 300 --output ethernet_capture.pcap &
sudo python3 shark.py --interface wlan0 --duration 300 --output wifi_capture.pcap &
wait
```

### 4. Filtreli İzleme (Gelişmiş)

```bash
# Sadece belirli IP aralığı
sudo python3 shark.py --interface eth0 --duration 300 --filter "host 192.168.1.100"

# Sadece HTTP trafiği
sudo python3 shark.py --interface eth0 --duration 300 --filter "port 80"

# DNS sorguları
sudo python3 shark.py --interface eth0 --duration 300 --filter "port 53"
```

## 🌐 Ağ Türlerine Göre Kullanım

### 1. Ev Ağı İzleme

```bash
# WiFi router analizi
sudo python3 shark.py --interface wlan0 --duration 600 --output home_network.pcap

# Bağlı cihazları tespit et
# Sonuç: Telefon, laptop, IoT cihazları
```

### 2. Ofis Ağı İzleme

```bash
# Ethernet ağı analizi
sudo python3 shark.py --interface eth0 --duration 1800 --output office_network.pcap

# Çalışan saatlerde izleme
sudo python3 shark.py --interface eth0 --duration 28800 --output workday_analysis.pcap
```

### 3. Sanal Ağ İzleme

```bash
# VirtualBox ağı
sudo python3 shark.py --interface vboxnet0 --duration 300 --output virtualbox_network.pcap

# VMware ağı
sudo python3 shark.py --interface vmnet8 --duration 300 --output vmware_network.pcap

# Docker ağı
sudo python3 shark.py --interface docker0 --duration 300 --output docker_network.pcap
```

### 4. Test Laboratuvarı

```bash
# İzole test ortamı
sudo python3 shark.py --interface test0 --duration 600 --output lab_network.pcap

# Penetrasyon testi ortamı
sudo python3 shark.py --interface eth0 --duration 1800 --output pentest_network.pcap
```

## 🛠️ Sorun Giderme Örnekleri

### 1. Yetki Sorunları

```bash
# Hata: Bu araç root yetkileri gerektirir!
# Çözüm:
sudo python3 shark.py --interface eth0

# Windows'ta:
# PowerShell'i Administrator olarak çalıştır
python shark.py --interface "Ethernet"
```

### 2. Ağ Arayüzü Bulunamadı

```bash
# Hata: Ağ arayüzü belirtilmedi
# Çözüm 1: Otomatik tespit
sudo python3 shark.py --auto-interface

# Çözüm 2: Mevcut arayüzleri listele
ip link show
# veya
ifconfig -a

# Çözüm 3: Manuel belirtme
sudo python3 shark.py --interface eth0
```

### 3. Kütüphane Eksiklikleri

```bash
# Hata: Gerekli kütüphane eksik: scapy
# Çözüm:
pip install scapy python-nmap requests

# Sistem seviyesi nmap:
sudo apt-get install nmap  # Ubuntu/Debian
sudo yum install nmap      # CentOS/RHEL
brew install nmap          # macOS
```

### 4. Paket Yakalama Sorunları

```bash
# Hata: Paket yakalama hatası
# Çözüm 1: Arayüz kontrolü
sudo ip link set eth0 up

# Çözüm 2: Promiscuous mode
sudo ip link set eth0 promisc on

# Çözüm 3: Firewall kontrolü
sudo ufw status
```

## 📊 Analiz ve Raporlama

### 1. PCAP Dosyası Analizi

```bash
# Wireshark ile açma
wireshark network_capture.pcap

# tcpdump ile analiz
tcpdump -r network_capture.pcap

# Tshark ile komut satırı analizi
tshark -r network_capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port
```

### 2. JSON Raporu Analizi

```bash
# Raporu görüntüle
cat network_capture_report.json | jq '.'

# Cihaz listesi
cat network_capture_report.json | jq '.active_devices[].ip'

# Trafik istatistikleri
cat network_capture_report.json | jq '.traffic_summary'
```

### 3. Log Dosyası Analizi

```bash
# Gerçek zamanlı log takibi
tail -f network_monitor.log

# Hata logları
grep "ERROR" network_monitor.log

# DNS sorguları
grep "DNS Sorgusu" network_monitor.log
```

### 4. Özel Analiz Scriptleri

```python
#!/usr/bin/env python3
# analyze_capture.py - Özel analiz scripti

import json
from scapy.all import *

def analyze_pcap(filename):
    """PCAP dosyasını analiz et"""
    packets = rdpcap(filename)
    
    print(f"📊 Toplam paket: {len(packets)}")
    
    # IP adresleri
    ips = set()
    for packet in packets:
        if IP in packet:
            ips.add(packet[IP].src)
            ips.add(packet[IP].dst)
    
    print(f"🌐 Benzersiz IP: {len(ips)}")
    
    # Protokol dağılımı
    protocols = {}
    for packet in packets:
        if IP in packet:
            proto = packet[IP].proto
            protocols[proto] = protocols.get(proto, 0) + 1
    
    print("📈 Protokol dağılımı:")
    for proto, count in protocols.items():
        print(f"   {proto}: {count}")

if __name__ == "__main__":
    analyze_pcap("network_capture.pcap")
```

## 🎯 Pratik Kullanım Senaryoları

### 1. Ağ Güvenliği Eğitimi

```bash
# Öğrenci laboratuvarı
sudo python3 shark.py --interface eth0 --duration 1800 --output security_lab.pcap

# Analiz:
# - Hangi cihazlar bağlı?
# - Hangi protokoller kullanılıyor?
# - Güvenlik açıkları var mı?
```

### 2. Ağ Performans Analizi

```bash
# Yavaş ağ tespiti
sudo python3 shark.py --interface eth0 --duration 600 --output performance_analysis.pcap

# Analiz:
# - Hangi cihazlar en çok trafik üretiyor?
# - Hangi protokoller kullanılıyor?
# - Ağ tıkanıklığı var mı?
```

### 3. IoT Cihaz Analizi

```bash
# Akıllı ev cihazları
sudo python3 shark.py --interface wlan0 --duration 3600 --output iot_devices.pcap

# Analiz:
# - Hangi IoT cihazları var?
# - Hangi sunuculara bağlanıyorlar?
# - Güvenlik riskleri var mı?
```

### 4. Ağ Forensik

```bash
# Olay müdahale
sudo python3 shark.py --interface eth0 --duration 7200 --output incident_response.pcap

# Analiz:
# - Şüpheli trafik var mı?
# - Hangi cihazlar etkilenmiş?
# - Saldırı vektörleri neler?
```

## 📚 Eğitim Kaynakları

### 1. Ağ Protokolleri Öğrenme

```bash
# TCP analizi
sudo python3 shark.py --interface eth0 --duration 300 --output tcp_analysis.pcap

# UDP analizi
sudo python3 shark.py --interface eth0 --duration 300 --output udp_analysis.pcap

# DNS analizi
sudo python3 shark.py --interface eth0 --duration 300 --output dns_analysis.pcap
```

### 2. Güvenlik Testleri

```bash
# Port tarama tespiti
sudo python3 shark.py --interface eth0 --duration 600 --output port_scan_detection.pcap

# DDoS tespiti
sudo python3 shark.py --interface eth0 --duration 300 --output ddos_detection.pcap

# Malware trafiği
sudo python3 shark.py --interface eth0 --duration 1800 --output malware_analysis.pcap
```

## 🔒 Güvenlik ve Etik Kullanım

### 1. Yasal Kullanım

```bash
# ✅ İzin verilen kullanımlar:
# - Kendi ev ağınız
# - İş yerinizde izinli kullanım
# - Eğitim laboratuvarı
# - Test ortamları

# ❌ Yasak kullanımlar:
# - Başkalarının ağları
# - İzinsiz ağ izleme
# - Kötü niyetli amaçlar
```

### 2. Gizlilik Koruması

```bash
# Hassas veri koruma
sudo python3 shark.py --interface eth0 --duration 300 --output secure_capture.pcap

# Analiz sonrası temizlik
rm -f *.pcap *.json *.log
```

### 3. Raporlama

```bash
# Eğitim raporu
sudo python3 shark.py --interface eth0 --duration 600 --output education_report.pcap

# Analiz sonuçları:
# - Tespit edilen cihazlar
# - Kullanılan protokoller
# - Güvenlik önerileri
```

---

⚠️ **SON UYARI**: Bu araç güçlü bir ağ izleme aracıdır. Sorumlu ve etik bir şekilde kullanın. Yasalara uygun olmayan kullanım sorumluluğu kullanıcıya aittir.

📞 **Destek**: Sorularınız için GitHub Issues kullanın.
