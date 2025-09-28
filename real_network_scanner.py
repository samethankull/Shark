#!/usr/bin/env python3
"""
Gerçek Ağ Tarayıcı
==================

Bu modül, gerçek ağ tarama yaparak cihaz bilgilerini toplar.
"""

import sys
import os
import time
import json
import subprocess
import re
import threading
from collections import defaultdict
import nmap
from advanced_device_detection import AdvancedDeviceDetector

class RealNetworkScanner:
    """Gerçek ağ tarayıcı sınıfı"""
    
    def __init__(self, network_range=None, output_file="real_network_scan.json"):
        self.network_range = network_range
        self.output_file = output_file
        self.nm = nmap.PortScanner()
        self.device_detector = AdvancedDeviceDetector()
        self.scan_results = {}
        
        print(f"🔍 Gerçek Ağ Tarayıcı başlatıldı")
        print(f"🌐 Ağ aralığı: {self.network_range}")
        print(f"💾 Çıktı dosyası: {self.output_file}")
    
    def discover_active_hosts(self):
        """Aktif hostları keşfet"""
        print(f"🔍 Aktif hostlar keşfediliyor: {self.network_range}")
        
        try:
            # Nmap ile ping taraması
            self.nm.scan(hosts=self.network_range, arguments='-sn')
            
            active_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    active_hosts.append(host)
                    print(f"✅ Aktif host: {host}")
            
            print(f"📊 Toplam {len(active_hosts)} aktif host bulundu")
            return active_hosts
            
        except Exception as e:
            print(f"❌ Host keşfi hatası: {e}")
            return []
    
    def get_mac_address(self, ip):
        """IP'nin MAC adresini al"""
        try:
            # ARP tablosundan MAC adresini al
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        # MAC adresini çıkar
                        mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line)
                        if mac_match:
                            return mac_match.group(1)
            
            # ARP tablosunda yoksa ARP isteği gönder
            from scapy.all import ARP, Ether, srp
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                return element[1].hwsrc
                
        except Exception as e:
            print(f"⚠️ MAC adresi alma hatası {ip}: {e}")
        
        return None
    
    def scan_host_ports(self, ip):
        """Host'un portlarını tara"""
        print(f"🔍 Port tarama: {ip}")
        
        try:
            # Hızlı port tarama
            self.nm.scan(hosts=ip, arguments='-sS -T4 --top-ports 1000')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                open_ports = []
                
                for protocol in host_info.all_protocols():
                    ports = host_info[protocol].keys()
                    for port in ports:
                        port_info = host_info[protocol][port]
                        if port_info['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            })
                
                return open_ports
                
        except Exception as e:
            print(f"⚠️ Port tarama hatası {ip}: {e}")
        
        return []
    
    def get_os_info(self, ip):
        """OS bilgilerini al"""
        print(f"🔍 OS tespiti: {ip}")
        
        try:
            # OS detection
            self.nm.scan(hosts=ip, arguments='-O --osscan-guess')
            
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                if 'osmatch' in host_info:
                    os_matches = host_info['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        return {
                            'os_name': best_match['name'],
                            'accuracy': best_match['accuracy'],
                            'os_class': best_match.get('osclass', [])
                        }
                        
        except Exception as e:
            print(f"⚠️ OS tespiti hatası {ip}: {e}")
        
        return None
    
    def scan_single_host(self, ip):
        """Tek host'u kapsamlı tara"""
        print(f"🎯 Host taranıyor: {ip}")
        
        # MAC adresini al
        mac = self.get_mac_address(ip)
        if not mac:
            print(f"⚠️ {ip} için MAC adresi alınamadı")
            return None
        
        print(f"🔗 {ip} -> {mac}")
        
        # Port tarama
        open_ports = self.scan_host_ports(ip)
        
        # OS tespiti
        os_info = self.get_os_info(ip)
        
        # Cihaz profili oluştur
        try:
            device_profile = self.device_detector.scan_device(ip, mac, [])
            
            # Gerçek tarama sonuçlarını ekle
            device_profile['real_scan'] = {
                'open_ports': open_ports,
                'os_info': os_info,
                'scan_timestamp': time.time()
            }
            
            return device_profile
            
        except Exception as e:
            print(f"⚠️ Cihaz profili oluşturma hatası {ip}: {e}")
            return None
    
    def scan_network(self):
        """Ağın tamamını tara"""
        print(f"🌐 Ağ tarama başlatılıyor: {self.network_range}")
        
        # Aktif hostları keşfet
        active_hosts = self.discover_active_hosts()
        
        if not active_hosts:
            print("❌ Aktif host bulunamadı!")
            return {}
        
        # Her host'u tara
        scan_results = {}
        for i, ip in enumerate(active_hosts, 1):
            print(f"\n📱 Host {i}/{len(active_hosts)}: {ip}")
            
            device_profile = self.scan_single_host(ip)
            if device_profile:
                scan_results[ip] = device_profile
                print(f"✅ {ip}: {device_profile['vendor']} - {device_profile['category']}")
            else:
                print(f"❌ {ip}: Tarama başarısız")
        
        self.scan_results = scan_results
        return scan_results
    
    def generate_report(self):
        """Rapor oluştur"""
        print(f"\n📊 Rapor oluşturuluyor...")
        
        # Cihaz özeti
        summary = self.device_detector.get_device_summary(self.scan_results)
        
        # Rapor oluştur
        report = {
            'timestamp': time.time(),
            'network_range': self.network_range,
            'scan_summary': summary,
            'devices': self.scan_results
        }
        
        # Raporu kaydet
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"✅ Rapor kaydedildi: {self.output_file}")
        
        # Özet yazdır
        print(f"\n📊 Tarama Özeti:")
        print(f"   🌐 Ağ Aralığı: {self.network_range}")
        print(f"   📱 Toplam Cihaz: {summary['total_devices']}")
        print(f"   🔌 IoT Cihazlar: {summary['iot_devices']}")
        print(f"   ⚠️  Yüksek Riskli: {summary['high_risk_devices']}")
        
        print(f"\n📂 Kategoriler:")
        for category, count in summary['categories'].items():
            print(f"   {category}: {count}")
        
        print(f"\n🏭 Vendors:")
        for vendor, count in summary['vendors'].items():
            print(f"   {vendor}: {count}")
        
        print(f"\n⚠️  Risk Seviyeleri:")
        for risk, count in summary['risk_levels'].items():
            print(f"   {risk}: {count}")
        
        return report

def main():
    """Ana fonksiyon"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Gerçek Ağ Tarayıcı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 real_network_scanner.py --network 192.168.1.0/24
  sudo python3 real_network_scanner.py --network 10.0.0.0/24 --output network_scan.json
  sudo python3 real_network_scanner.py --network 172.16.0.0/16 --verbose

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
        """
    )
    
    parser.add_argument('--network', '-n', required=True,
                       help='Ağ aralığı (örn: 192.168.1.0/24)')
    parser.add_argument('--output', '-o', default='real_network_scan.json',
                       help='Çıktı dosyası (varsayılan: real_network_scan.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    # Uyarı mesajı
    print("⚠️" * 20)
    print("GERÇEK AĞ TARAYICI")
    print("⚠️" * 20)
    print("Bu araç yalnızca eğitim ve akademik amaçlı geliştirilmiştir.")
    print("Yalnızca kendi sahip olduğunuz ağlarda kullanın.")
    print("⚠️" * 20)
    
    # Yetki kontrolü
    if os.geteuid() != 0:
        print("\n❌ Bu araç root yetkileri gerektirir!")
        print("Linux/macOS: sudo python3 real_network_scanner.py")
        print("Windows: Administrator olarak çalıştırın")
        sys.exit(1)
    
    # Scanner oluştur
    scanner = RealNetworkScanner(network_range=args.network, output_file=args.output)
    
    try:
        # Ağ tarama
        scan_results = scanner.scan_network()
        
        if scan_results:
            # Rapor oluştur
            scanner.generate_report()
            print(f"\n✅ Tarama tamamlandı!")
        else:
            print(f"\n❌ Tarama başarısız!")
    
    except KeyboardInterrupt:
        print("\n⏹️  Tarama kullanıcı tarafından durduruldu")
        if scanner.scan_results:
            scanner.generate_report()
        
    except Exception as e:
        print(f"❌ Genel hata: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()



