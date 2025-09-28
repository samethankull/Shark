#!/usr/bin/env python3
"""
Gerçek Zamanlı Web Aktivite İzleme
==================================

Bu modül, gerçek ağ trafiğini analiz ederek web aktivitelerini izler.
"""

import sys
import os
import time
import threading
import json
from collections import defaultdict, Counter
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from web_activity_monitor import WebActivityMonitor

class RealTimeWebMonitor:
    """Gerçek zamanlı web aktivite izleme sınıfı"""
    
    def __init__(self, interface=None, output_file="real_time_web_activity.json"):
        self.interface = interface
        self.output_file = output_file
        self.web_monitor = WebActivityMonitor()
        self.running = False
        self.captured_packets = []
        self.packet_count = 0
        
        # İstatistikler
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'http_packets': 0,
            'https_packets': 0,
            'unique_ips': set(),
            'unique_domains': set()
        }
        
        print(f"🌐 Gerçek Zamanlı Web Aktivite İzleyici başlatıldı")
        print(f"📡 Ağ arayüzü: {self.interface}")
        print(f"💾 Çıktı dosyası: {self.output_file}")
    
    def packet_handler(self, packet):
        """Paket yakalama ve analiz"""
        if not self.running:
            return
        
        try:
            self.packet_count += 1
            self.stats['total_packets'] += 1
            
            # IP katmanı kontrolü
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            # İstatistikleri güncelle
            self.stats['unique_ips'].add(src_ip)
            
            # DNS analizi
            if protocol == 17 and packet.haslayer(DNS):  # UDP + DNS
                self.analyze_dns_packet(packet, src_ip)
            
            # HTTP analizi
            elif protocol == 6 and packet.haslayer(Raw):  # TCP + Raw data
                self.analyze_http_packet(packet, src_ip, dst_ip)
            
            # HTTPS analizi
            elif protocol == 6 and packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                if tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    self.analyze_https_packet(packet, src_ip, dst_ip)
            
            # Her 100 pakette bir istatistik yazdır
            if self.packet_count % 100 == 0:
                self.print_stats()
                
        except Exception as e:
            print(f"⚠️ Paket analiz hatası: {e}")
    
    def analyze_dns_packet(self, packet, src_ip):
        """DNS paketini analiz et"""
        try:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # DNS sorgusu
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                
                # Web aktivite modülüne gönder
                self.web_monitor.analyze_dns_query(src_ip, query_name)
                
                # İstatistikleri güncelle
                self.stats['dns_packets'] += 1
                self.stats['unique_domains'].add(query_name)
                
                print(f"🔍 DNS: {src_ip} -> {query_name}")
                
        except Exception as e:
            print(f"⚠️ DNS analiz hatası: {e}")
    
    def analyze_http_packet(self, packet, src_ip, dst_ip):
        """HTTP paketini analiz et"""
        try:
            raw_data = packet[Raw].load
            
            # HTTP başlığını kontrol et
            if b'HTTP' in raw_data and (b'GET' in raw_data or b'POST' in raw_data or b'PUT' in raw_data):
                http_data = raw_data.decode('utf-8', errors='ignore')
                lines = http_data.split('\n')
                
                host = None
                path = None
                user_agent = None
                
                # HTTP başlıklarını parse et
                for line in lines[:20]:  # İlk 20 satırı kontrol et
                    line = line.strip()
                    if line.startswith('Host:'):
                        host = line.split(':', 1)[1].strip()
                    elif line.startswith('User-Agent:'):
                        user_agent = line.split(':', 1)[1].strip()
                    elif line.startswith('GET ') or line.startswith('POST ') or line.startswith('PUT '):
                        path = line.split(' ')[1]
                
                if host:
                    # Web aktivite modülüne gönder
                    self.web_monitor.analyze_http_request(src_ip, host, path or "/", user_agent)
                    
                    # İstatistikleri güncelle
                    self.stats['http_packets'] += 1
                    self.stats['unique_domains'].add(host)
                    
                    print(f"🌍 HTTP: {src_ip} -> {host}{path or '/'}")
                    
        except Exception as e:
            print(f"⚠️ HTTP analiz hatası: {e}")
    
    def analyze_https_packet(self, packet, src_ip, dst_ip):
        """HTTPS paketini analiz et"""
        try:
            tcp_layer = packet[TCP]
            
            # SNI (Server Name Indication) tespiti
            sni = None
            if tcp_layer.dport == 443:
                # TLS Client Hello paketinde SNI arama
                raw_data = packet[Raw].load if packet.haslayer(Raw) else b''
                if b'\x00\x00' in raw_data:  # TLS handshake
                    # Basit SNI çıkarma (gerçek implementasyon daha karmaşık olmalı)
                    sni = dst_ip  # Geçici olarak hedef IP kullan
            
            # Web aktivite modülüne gönder
            self.web_monitor.analyze_https_connection(src_ip, dst_ip, tcp_layer.dport, sni)
            
            # İstatistikleri güncelle
            self.stats['https_packets'] += 1
            
            print(f"🔒 HTTPS: {src_ip} -> {dst_ip}:{tcp_layer.dport}")
            
        except Exception as e:
            print(f"⚠️ HTTPS analiz hatası: {e}")
    
    def print_stats(self):
        """İstatistikleri yazdır"""
        print(f"\n📊 İstatistikler (Paket #{self.packet_count}):")
        print(f"   📦 Toplam Paket: {self.stats['total_packets']}")
        print(f"   🔍 DNS Paketleri: {self.stats['dns_packets']}")
        print(f"   🌍 HTTP Paketleri: {self.stats['http_packets']}")
        print(f"   🔒 HTTPS Paketleri: {self.stats['https_packets']}")
        print(f"   👥 Benzersiz IP: {len(self.stats['unique_ips'])}")
        print(f"   🌐 Benzersiz Domain: {len(self.stats['unique_domains'])}")
    
    def start_monitoring(self, duration=None):
        """İzlemeyi başlat"""
        print(f"🚀 Gerçek zamanlı web aktivite izleme başlatılıyor...")
        print(f"⏱️  Süre: {duration} saniye" if duration else "⏱️  Süre: Sınırsız")
        print("⏹️  Durdurmak için Ctrl+C kullanın")
        
        self.running = True
        
        def monitor():
            try:
                # Paket yakalama başlat
                sniff(iface=self.interface, 
                      prn=self.packet_handler, 
                      timeout=duration,
                      store=0)
            except Exception as e:
                print(f"❌ Paket yakalama hatası: {e}")
            finally:
                self.running = False
        
        # İzleme thread'ini başlat
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return monitor_thread
    
    def stop_monitoring(self):
        """İzlemeyi durdur"""
        print("\n⏹️  İzleme durduruluyor...")
        self.running = False
    
    def generate_report(self):
        """Rapor oluştur"""
        print(f"\n📊 Rapor oluşturuluyor...")
        
        # Web aktivite raporu
        self.web_monitor.generate_web_activity_report(self.output_file)
        
        # İstatistik raporu
        stats_report = {
            'timestamp': time.time(),
            'monitoring_stats': {
                'total_packets': self.stats['total_packets'],
                'dns_packets': self.stats['dns_packets'],
                'http_packets': self.stats['http_packets'],
                'https_packets': self.stats['https_packets'],
                'unique_ips': list(self.stats['unique_ips']),
                'unique_domains': list(self.stats['unique_domains'])
            }
        }
        
        stats_file = self.output_file.replace('.json', '_stats.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats_report, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"✅ Raporlar kaydedildi:")
        print(f"   📄 Web aktivite: {self.output_file}")
        print(f"   📊 İstatistikler: {stats_file}")
        
        # Aktivite özetini yazdır
        self.web_monitor.print_activity_summary()

def main():
    """Ana fonksiyon"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Gerçek Zamanlı Web Aktivite İzleyici",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 real_time_web_monitor.py --interface eth0 --duration 300
  sudo python3 real_time_web_monitor.py --auto-interface --duration 600
  sudo python3 real_time_web_monitor.py --interface wlan0 --output web_activity.json

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
        """
    )
    
    parser.add_argument('--interface', '-i', 
                       help='Ağ arayüzü (örn: eth0, wlan0)')
    parser.add_argument('--auto-interface', '-a', action='store_true',
                       help='Otomatik ağ arayüzü tespit et')
    parser.add_argument('--duration', '-d', type=int, default=300,
                       help='İzleme süresi (saniye, varsayılan: 300)')
    parser.add_argument('--output', '-o', default='real_time_web_activity.json',
                       help='Çıktı dosyası (varsayılan: real_time_web_activity.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    # Uyarı mesajı
    print("⚠️" * 20)
    print("GERÇEK ZAMANLI WEB AKTİVİTE İZLEYİCİ")
    print("⚠️" * 20)
    print("Bu araç yalnızca eğitim ve akademik amaçlı geliştirilmiştir.")
    print("Yalnızca kendi sahip olduğunuz veya izleme izniniz olan ağlarda kullanın.")
    print("⚠️" * 20)
    
    # Yetki kontrolü
    if os.geteuid() != 0:
        print("\n❌ Bu araç root yetkileri gerektirir!")
        print("Linux/macOS: sudo python3 real_time_web_monitor.py")
        print("Windows: Administrator olarak çalıştırın")
        sys.exit(1)
    
    # Ağ arayüzü belirleme
    interface = args.interface
    if args.auto_interface and not interface:
        # Otomatik tespit
        try:
            import subprocess
            import re
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r'dev (\w+)', result.stdout)
                if match:
                    interface = match.group(1)
                    print(f"🔍 Otomatik ağ arayüzü: {interface}")
        except:
            pass
    
    if not interface:
        print("❌ Ağ arayüzü belirtilmedi. --interface veya --auto-interface kullanın.")
        sys.exit(1)
    
    # Monitor oluştur
    monitor = RealTimeWebMonitor(interface=interface, output_file=args.output)
    
    try:
        # İzleme başlat
        monitor_thread = monitor.start_monitoring(duration=args.duration)
        
        # İzleme süresini bekle
        monitor_thread.join()
        
        # Rapor oluştur
        monitor.generate_report()
        
        print(f"\n✅ İzleme tamamlandı!")
        
    except KeyboardInterrupt:
        print("\n⏹️  İzleme kullanıcı tarafından durduruldu")
        monitor.stop_monitoring()
        monitor.generate_report()
        
    except Exception as e:
        print(f"❌ Genel hata: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()



