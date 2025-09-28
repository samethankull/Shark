#!/usr/bin/env python3
"""
ETİK AĞ İZLEME ARACI - ACADEMIC NETWORK MONITOR
==============================================

⚠️  UYARI: Bu araç yalnızca eğitim ve akademik amaçlı geliştirilmiştir.
    Yalnızca kendi sahip olduğunuz veya izleme izniniz olan ağlarda kullanın.
    Yasalara uygun şekilde kullanım sorumluluğu kullanıcıya aittir.

Özellikler:
- Aktif IP adreslerini tespit etme
- MAC adresi eşleştirme
- Cihaz türü tanımlama (OUI lookup)
- Ağ trafiği izleme ve analiz
- PCAP dosyasına kaydetme
- Wireshark uyumlu çıktı

Gereksinimler:
- Python 3.6+
- Root/Administrator yetkileri
- scapy, python-nmap, requests kütüphaneleri
- nmap (sistem seviyesinde kurulu)

Kullanım:
    sudo python3 shark.py --interface eth0 --duration 300 --output network_capture.pcap
"""

import argparse
import logging
import os
import sys
import time
import json
import threading
from datetime import datetime
from collections import defaultdict, Counter
import subprocess
import re

# Temel kütüphaneler - hızlı yükleme
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    import nmap
    import requests
except ImportError as e:
    print(f"❌ Gerekli kütüphane eksik: {e}")
    print("Kurulum için: pip install scapy python-nmap requests")
    sys.exit(1)

# İsteğe bağlı kütüphaneler - lazy loading
networkx = None
matplotlib = None

# Gelişmiş modüller - lazy loading
AdvancedDeviceDetector = None
NetworkTopologyMapper = None
PenetrationTester = None
WebActivityMonitor = None
WiFiNetworkScanner = None

def load_advanced_modules():
    """Gelişmiş modülleri sadece gerektiğinde yükle"""
    global AdvancedDeviceDetector, NetworkTopologyMapper, PenetrationTester, WebActivityMonitor, WiFiNetworkScanner
    
    if AdvancedDeviceDetector is None:
        try:
            from real_network_scanner import RealNetworkScanner as AdvancedDeviceDetector
            print("✅ RealNetworkScanner yüklendi")
        except ImportError as e:
            print(f"⚠️ RealNetworkScanner bulunamadı: {e}")
            AdvancedDeviceDetector = False
    
    if NetworkTopologyMapper is None:
        try:
            from real_topology_mapper import RealTopologyMapper as NetworkTopologyMapper
            print("✅ RealTopologyMapper yüklendi")
        except ImportError as e:
            print(f"⚠️ RealTopologyMapper bulunamadı: {e}")
            NetworkTopologyMapper = False
    
    if PenetrationTester is None:
        try:
            from real_penetration_tester import RealPenetrationTester as PenetrationTester
            print("✅ RealPenetrationTester yüklendi")
        except ImportError as e:
            print(f"⚠️ RealPenetrationTester bulunamadı: {e}")
            PenetrationTester = False
    
    if WebActivityMonitor is None:
        try:
            from real_time_web_monitor import RealTimeWebMonitor as WebActivityMonitor
            print("✅ RealTimeWebMonitor yüklendi")
        except ImportError as e:
            print(f"⚠️ RealTimeWebMonitor bulunamadı: {e}")
            WebActivityMonitor = False
    
    if WiFiNetworkScanner is None:
        try:
            from wifi_network_scanner import WiFiNetworkScanner
            print("✅ WiFiNetworkScanner yüklendi")
        except ImportError as e:
            print(f"⚠️ WiFiNetworkScanner bulunamadı: {e}")
            WiFiNetworkScanner = False

# Logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkMonitor:
    """Ana ağ izleme sınıfı"""
    
    def __init__(self, interface=None, output_file="network_capture.pcap", advanced_mode=False, web_activity_mode=False):
        self.interface = interface
        self.output_file = output_file
        self.advanced_mode = advanced_mode
        self.web_activity_mode = web_activity_mode
        self.active_ips = set()
        self.mac_to_ip = {}
        self.ip_to_mac = {}
        self.device_info = {}
        self.traffic_stats = defaultdict(Counter)
        self.captured_packets = []
        self.running = False
        self.nm = nmap.PortScanner()
        
        # Gelişmiş modüller
        self.device_detector = None
        self.topology_mapper = None
        self.penetration_tester = None
        self.web_activity_monitor = None
        
        # Modülleri sadece gerektiğinde yükle
        if self.advanced_mode or self.web_activity_mode:
            load_advanced_modules()
        
        # Web aktivite modülü (sadece gerektiğinde yükle)
        if self.web_activity_mode and WebActivityMonitor:
            try:
                self.web_activity_monitor = WebActivityMonitor()
                print("✅ WebActivityMonitor başlatıldı")
            except Exception as e:
                print(f"⚠️ WebActivityMonitor başlatılamadı: {e}")
                self.web_activity_monitor = None
        
        if self.advanced_mode:
            if AdvancedDeviceDetector:
                self.device_detector = AdvancedDeviceDetector()
                print("✅ AdvancedDeviceDetector başlatıldı")
            
            if NetworkTopologyMapper:
                self.topology_mapper = NetworkTopologyMapper()
                print("✅ NetworkTopologyMapper başlatıldı")
            
            if PenetrationTester:
                self.penetration_tester = PenetrationTester()
                print("✅ PenetrationTester başlatıldı")
        
        # OUI veritabanı (kısaltılmış)
        self.oui_database = {
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "00:0c:29": "VMware",
            "00:1c:42": "Parallels",
            "00:15:5d": "Microsoft Hyper-V",
            "00:16:3e": "Xen",
            "00:1b:21": "Intel",
            "00:1f:5b": "Apple",
            "00:23:12": "Apple",
            "00:25:00": "Apple",
            "00:26:bb": "Apple",
            "00:26:4a": "Apple",
            "00:26:b0": "Apple",
            "00:26:08": "Apple",
            "00:25:4b": "Apple",
            "00:25:bc": "Apple",
            "00:25:00": "Apple",
            "00:1f:f3": "Apple",
            "00:1f:f4": "Apple",
            "00:1f:f5": "Apple",
            "00:1f:f6": "Apple",
            "00:1f:f7": "Apple",
            "00:1f:f8": "Apple",
            "00:1f:f9": "Apple",
            "00:1f:fa": "Apple",
            "00:1f:fb": "Apple",
            "00:1f:fc": "Apple",
            "00:1f:fd": "Apple",
            "00:1f:fe": "Apple",
            "00:1f:ff": "Apple",
            "00:23:6c": "Apple",
            "00:23:df": "Apple",
            "00:23:12": "Apple",
            "00:25:00": "Apple",
            "00:25:4b": "Apple",
            "00:25:bc": "Apple",
            "00:26:08": "Apple",
            "00:26:4a": "Apple",
            "00:26:bb": "Apple",
            "00:26:b0": "Apple",
            "00:1b:21": "Intel",
            "00:1c:42": "Parallels",
            "00:0c:29": "VMware",
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "00:15:5d": "Microsoft Hyper-V",
            "00:16:3e": "Xen"
        }
        
        logger.info("🔍 Network Monitor başlatıldı")
        logger.info(f"📡 Ağ arayüzü: {self.interface}")
        logger.info(f"💾 Çıktı dosyası: {self.output_file}")
    
    def check_permissions(self):
        """Root yetkilerini kontrol et"""
        if os.geteuid() != 0:
            logger.error("❌ Bu araç root yetkileri gerektirir!")
            logger.error("Linux/macOS: sudo python3 shark.py")
            logger.error("Windows: Administrator olarak çalıştırın")
            return False
        return True
    
    def get_network_info(self):
        """Ağ bilgilerini al"""
        try:
            if not self.interface:
                # Varsayılan ağ arayüzünü bul
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    match = re.search(r'dev (\w+)', result.stdout)
                    if match:
                        self.interface = match.group(1)
                        logger.info(f"🔍 Otomatik ağ arayüzü tespit edildi: {self.interface}")
            
            # Ağ adresini al
            result = subprocess.run(['ip', 'addr', 'show', self.interface], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # IP adresini çıkar
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', result.stdout)
                if ip_match:
                    ip = ip_match.group(1)
                    network = '.'.join(ip.split('.')[:-1]) + '.0/24'
                    logger.info(f"🌐 Ağ: {network}")
                    return network
            
        except Exception as e:
            logger.error(f"❌ Ağ bilgileri alınamadı: {e}")
        
        return None
    
    def scan_network(self, network):
        """Ağdaki aktif IP'leri tara"""
        logger.info(f"🔍 Ağ taranıyor: {network}")
        
        try:
            # Nmap ile hızlı ping taraması
            self.nm.scan(hosts=network, arguments='-sn')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    self.active_ips.add(host)
                    logger.info(f"✅ Aktif IP: {host}")
            
            logger.info(f"📊 Toplam {len(self.active_ips)} aktif IP bulundu")
            
        except Exception as e:
            logger.error(f"❌ Ağ tarama hatası: {e}")
    
    def get_mac_addresses(self):
        """IP'lerin MAC adreslerini al"""
        logger.info("🔍 MAC adresleri tespit ediliyor...")
        
        for ip in self.active_ips:
            try:
                # ARP isteği gönder
                arp_request = ARP(pdst=ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
                
                for element in answered_list:
                    mac = element[1].hwsrc
                    self.ip_to_mac[ip] = mac
                    self.mac_to_ip[mac] = ip
                    logger.info(f"🔗 {ip} -> {mac}")
                    
            except Exception as e:
                logger.warning(f"⚠️ {ip} için MAC adresi alınamadı: {e}")
    
    def advanced_device_scanning(self):
        """Gelişmiş cihaz tarama"""
        if not self.advanced_mode or not self.device_detector:
            return
        
        logger.info("🔍 Gelişmiş cihaz tarama başlatılıyor...")
        
        device_profiles = {}
        
        for ip, mac in self.ip_to_mac.items():
            try:
                # Gelişmiş cihaz profili oluştur
                profile = self.device_detector.scan_device(ip, mac, self.captured_packets)
                device_profiles[ip] = profile
                
                logger.info(f"📱 {ip}: {profile['vendor']} - {profile['category']} (Risk: {profile['risk_level']})")
                
            except Exception as e:
                logger.warning(f"⚠️ Gelişmiş tarama hatası {ip}: {e}")
        
        # Cihaz özeti
        if device_profiles:
            summary = self.device_detector.get_device_summary(device_profiles)
            logger.info(f"📊 Toplam {summary['total_devices']} cihaz, {summary['iot_devices']} IoT cihaz, {summary['high_risk_devices']} yüksek riskli cihaz")
        
        return device_profiles
    
    def analyze_network_topology(self, device_profiles):
        """Ağ topolojisini analiz et"""
        if not self.advanced_mode or not self.topology_mapper:
            return None
        
        logger.info("🌐 Ağ topolojisi analiz ediliyor...")
        
        try:
            # Cihaz listesi hazırla
            devices = []
            for ip, profile in device_profiles.items():
                devices.append({
                    'ip': ip,
                    'mac': profile['mac'],
                    'vendor': profile['vendor'],
                    'category': profile['category'],
                    'device_type': profile['category'],
                    'open_ports': profile['open_ports']
                })
            
            # Topoloji analizi
            topology_analysis = self.topology_mapper.analyze_network_topology(devices, self.captured_packets)
            
            # Topoloji görselleştirme
            if topology_analysis:
                self.topology_mapper.visualize_topology(f"{self.output_file.replace('.pcap', '_topology.png')}")
                self.topology_mapper.export_topology_data(f"{self.output_file.replace('.pcap', '_topology_data.json')}")
                self.topology_mapper.generate_topology_report(topology_analysis, f"{self.output_file.replace('.pcap', '_topology_report.json')}")
            
            logger.info(f"📊 Topoloji analizi tamamlandı: {topology_analysis['total_devices']} cihaz, {topology_analysis['total_connections']} bağlantı")
            
            return topology_analysis
            
        except Exception as e:
            logger.error(f"❌ Topoloji analizi hatası: {e}")
            return None
    
    def run_penetration_tests(self, device_profiles):
        """Penetrasyon testleri çalıştır"""
        if not self.advanced_mode or not self.penetration_tester:
            return None
        
        logger.info("🔒 Penetrasyon testleri başlatılıyor...")
        
        penetration_results = {}
        
        try:
            for ip, profile in device_profiles.items():
                # Yüksek riskli cihazları test et
                if profile['risk_level'] in ['High', 'Critical']:
                    logger.info(f"🔍 Penetrasyon testi: {ip}")
                    
                    test_result = self.penetration_tester.run_comprehensive_test(ip)
                    penetration_results[ip] = test_result
                    
                    # Rapor oluştur
                    self.penetration_tester.generate_penetration_report(
                        test_result, 
                        f"{self.output_file.replace('.pcap', f'_penetration_{ip.replace('.', '_')}.json')}"
                    )
                    
                    logger.info(f"🔒 {ip} penetrasyon testi tamamlandı - Risk: {test_result['risk_score']}")
            
            # Genel penetrasyon raporu
            if penetration_results:
                self.generate_combined_penetration_report(penetration_results)
            
            return penetration_results
            
        except Exception as e:
            logger.error(f"❌ Penetrasyon testi hatası: {e}")
            return None
    
    def generate_combined_penetration_report(self, penetration_results):
        """Birleşik penetrasyon raporu oluştur"""
        try:
            combined_report = {
                'timestamp': time.time(),
                'total_targets': len(penetration_results),
                'high_risk_targets': 0,
                'critical_vulnerabilities': 0,
                'total_vulnerabilities': 0,
                'targets': penetration_results,
                'overall_risk_score': 0
            }
            
            # İstatistikleri hesapla
            for ip, result in penetration_results.items():
                combined_report['total_vulnerabilities'] += len(result['vulnerabilities'])
                combined_report['overall_risk_score'] += result['risk_score']
                
                if result['risk_score'] >= 75:
                    combined_report['high_risk_targets'] += 1
                
                for vuln in result['vulnerabilities']:
                    if vuln['risk'] == 'Critical':
                        combined_report['critical_vulnerabilities'] += 1
            
            # Ortalama risk skoru
            if penetration_results:
                combined_report['overall_risk_score'] = combined_report['overall_risk_score'] / len(penetration_results)
            
            # Raporu kaydet
            report_file = f"{self.output_file.replace('.pcap', '_combined_penetration_report.json')}"
            with open(report_file, 'w') as f:
                json.dump(combined_report, f, indent=2, default=str)
            
            logger.info(f"📊 Birleşik penetrasyon raporu: {report_file}")
            
        except Exception as e:
            logger.error(f"❌ Birleşik rapor oluşturma hatası: {e}")
    
    def generate_web_activity_report(self):
        """Web aktivite raporu oluştur"""
        if not self.web_activity_monitor:
            logger.warning("⚠️ Web aktivite modülü yüklü değil")
            return
        
        logger.info("🌐 Web aktivite raporu oluşturuluyor...")
        
        try:
            # Web aktivite raporu oluştur
            report_file = f"{self.output_file.replace('.pcap', '_web_activity_report.json')}"
            self.web_activity_monitor.generate_web_activity_report(report_file)
            
            # Aktivite özetini yazdır
            self.web_activity_monitor.print_activity_summary()
            
            logger.info(f"✅ Web aktivite raporu oluşturuldu: {report_file}")
            
        except Exception as e:
            logger.error(f"❌ Web aktivite raporu hatası: {e}")
            import traceback
            traceback.print_exc()
    
    def identify_device_type(self, mac_address):
        """MAC adresinden cihaz türünü tespit et"""
        if not mac_address:
            return "Bilinmeyen"
        
        oui = mac_address[:8].upper()
        
        # OUI veritabanından kontrol et
        if oui in self.oui_database:
            return self.oui_database[oui]
        
        # Online OUI lookup (isteğe bağlı)
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass
        
        return "Bilinmeyen Cihaz"
    
    def packet_handler(self, packet):
        """Paket yakalama ve analiz - Optimize edilmiş"""
        if not self.running:
            return
        
        try:
            # Paketi kaydet (sadece gerekirse)
            if len(self.captured_packets) < 10000:  # Limit koy
                self.captured_packets.append(packet)
            
            # IP katmanı kontrolü - hızlı erişim
            if not hasattr(packet, 'haslayer') or not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            # Trafik istatistikleri - optimize edilmiş
            self.traffic_stats[src_ip]['packets_sent'] += 1
            self.traffic_stats[dst_ip]['packets_received'] += 1
            
            # Protokol analizi - hızlı switch
            if protocol == 6:  # TCP
                self.traffic_stats[src_ip]['tcp_packets'] += 1
            elif protocol == 17:  # UDP
                self.traffic_stats[src_ip]['udp_packets'] += 1
            elif protocol == 1:  # ICMP
                self.traffic_stats[src_ip]['icmp_packets'] += 1
                
            # DNS sorguları - optimize edilmiş
            if protocol == 17 and packet.haslayer(DNS):  # UDP + DNS
                dns_query = packet[DNS]
                if dns_query.qr == 0:  # Sorgu
                    try:
                        query_name = dns_query.qd.qname.decode('utf-8').rstrip('.')
                        logger.info(f"🌐 DNS Sorgusu: {src_ip} -> {query_name}")
                        self.traffic_stats[src_ip]['dns_queries'].append(query_name)
                        
                        # Web aktivite izleme - sadece gerekirse
                        if self.web_activity_monitor:
                            self.web_activity_monitor.analyze_dns_query(src_ip, query_name)
                    except:
                        pass
                
            # HTTP trafiği - optimize edilmiş
            if protocol == 6 and packet.haslayer(Raw):  # TCP + Raw data
                raw_data = packet[Raw].load
                if b'HTTP' in raw_data and (b'GET' in raw_data or b'POST' in raw_data):
                    try:
                        http_data = raw_data.decode('utf-8', errors='ignore')
                        lines = http_data.split('\n')
                        host = None
                        path = None
                        
                        # Sadece ilk birkaç satırı kontrol et (hızlı)
                        for line in lines[:10]:
                            if line.startswith('Host:'):
                                host = line.split(':', 1)[1].strip()
                                break
                            elif line.startswith('GET ') or line.startswith('POST '):
                                path = line.split(' ')[1]
                        
                        if host:
                            logger.info(f"🌍 HTTP: {src_ip} -> {host}{path}")
                            self.traffic_stats[src_ip]['http_requests'].append(host)
                            
                            # Web aktivite izleme - sadece gerekirse
                            if self.web_activity_monitor:
                                self.web_activity_monitor.analyze_http_request(src_ip, host, path)
                    except:
                        pass
                
            # HTTPS trafiği - optimize edilmiş
            if protocol == 6 and packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                if tcp_layer.dport == 443:
                    logger.info(f"🔒 HTTPS: {src_ip} -> {dst_ip}:443")
                    self.traffic_stats[src_ip]['https_connections'] += 1
                    
                    # Web aktivite izleme - sadece gerekirse
                    if self.web_activity_monitor:
                        self.web_activity_monitor.analyze_https_connection(src_ip, dst_ip, 443)
                
        except Exception as e:
            logger.warning(f"⚠️ Paket analiz hatası: {e}")
    
    def start_monitoring(self, duration=None):
        """Ağ izlemeyi başlat"""
        logger.info("🚀 Ağ izleme başlatılıyor...")
        
        self.running = True
        
        def monitor():
            try:
                # Paket yakalama başlat
                sniff(iface=self.interface, 
                      prn=self.packet_handler, 
                      timeout=duration,
                      store=0)
            except Exception as e:
                logger.error(f"❌ Paket yakalama hatası: {e}")
            finally:
                self.running = False
        
        # İzleme thread'ini başlat
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return monitor_thread
    
    def save_pcap(self):
        """Yakalanan paketleri PCAP dosyasına kaydet"""
        if not self.captured_packets:
            logger.warning("⚠️ Kaydedilecek paket bulunamadı")
            return
        
        try:
            wrpcap(self.output_file, self.captured_packets)
            logger.info(f"💾 {len(self.captured_packets)} paket {self.output_file} dosyasına kaydedildi")
        except Exception as e:
            logger.error(f"❌ PCAP kaydetme hatası: {e}")
    
    def generate_report(self):
        """Detaylı rapor oluştur"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "interface": self.interface,
            "active_devices": [],
            "traffic_summary": {},
            "network_analysis": {}
        }
        
        # Cihaz bilgileri
        for ip, mac in self.ip_to_mac.items():
            device_type = self.identify_device_type(mac)
            device_info = {
                "ip": ip,
                "mac": mac,
                "device_type": device_type,
                "traffic_stats": dict(self.traffic_stats.get(ip, {}))
            }
            report["active_devices"].append(device_info)
        
        # Trafik özeti
        total_packets = sum(len(dev["traffic_stats"].get("packets_sent", [])) 
                          for dev in report["active_devices"])
        report["traffic_summary"] = {
            "total_devices": len(self.active_ips),
            "total_packets": len(self.captured_packets),
            "monitoring_duration": "N/A"  # Duration bilgisi eklenecek
        }
        
        # Raporu kaydet
        report_file = self.output_file.replace('.pcap', '_report.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📊 Detaylı rapor: {report_file}")
        return report
    
    def print_summary(self):
        """Özet bilgileri yazdır"""
        print("\n" + "="*60)
        print("🔍 AĞ İZLEME RAPORU")
        print("="*60)
        
        print(f"📡 Ağ Arayüzü: {self.interface}")
        print(f"🌐 Aktif Cihazlar: {len(self.active_ips)}")
        print(f"📦 Yakalanan Paketler: {len(self.captured_packets)}")
        print(f"💾 PCAP Dosyası: {self.output_file}")
        
        print("\n📱 TESPİT EDİLEN CİHAZLAR:")
        print("-" * 40)
        for ip, mac in self.ip_to_mac.items():
            device_type = self.identify_device_type(mac)
            print(f"🔗 {ip:15} | {mac:17} | {device_type}")
        
        print("\n📊 TRAFİK İSTATİSTİKLERİ:")
        print("-" * 40)
        for ip, stats in self.traffic_stats.items():
            if stats:
                print(f"🌐 {ip}:")
                for stat_type, value in stats.items():
                    if isinstance(value, list):
                        print(f"   {stat_type}: {len(value)}")
                    else:
                        print(f"   {stat_type}: {value}")
        
        print("\n" + "="*60)

def main():
    """Ana fonksiyon"""
    parser = argparse.ArgumentParser(
        description="Etik Ağ İzleme Aracı - Academic Network Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 shark.py --interface eth0 --duration 300 --output capture.pcap
  sudo python3 shark.py --auto-interface --duration 600
  sudo python3 shark.py --interface wlan0 --output wifi_analysis.pcap

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır. Yasalara uygun kullanın!
        """
    )
    
    parser.add_argument('--interface', '-i', 
                       help='Ağ arayüzü (örn: eth0, wlan0)')
    parser.add_argument('--auto-interface', '-a', action='store_true',
                       help='Otomatik ağ arayüzü tespit et')
    parser.add_argument('--duration', '-d', type=int, default=300,
                       help='İzleme süresi (saniye, varsayılan: 300)')
    parser.add_argument('--output', '-o', default='network_capture.pcap',
                       help='Çıktı PCAP dosyası (varsayılan: network_capture.pcap)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    parser.add_argument('--advanced', '-A', action='store_true',
                       help='Gelişmiş özellikler (cihaz tanımlama, topoloji, penetrasyon testi)')
    parser.add_argument('--topology', '-t', action='store_true',
                       help='Ağ topolojisi analizi')
    parser.add_argument('--penetration', '-p', action='store_true',
                       help='Penetrasyon testleri')
    parser.add_argument('--web-activity', '-w', action='store_true',
                       help='Web aktivite izleme (hangi sitelere gidildiği, arama sorguları)')
    parser.add_argument('--fast', '-f', action='store_true',
                       help='Hızlı mod (sadece temel özellikler, daha hızlı başlatma)')
    
    args = parser.parse_args()
    
    # Uyarı mesajı
    print("⚠️" * 20)
    print("ETİK AĞ İZLEME ARACI - ACADEMIC NETWORK MONITOR")
    print("⚠️" * 20)
    print("Bu araç yalnızca eğitim ve akademik amaçlı geliştirilmiştir.")
    print("Yalnızca kendi sahip olduğunuz veya izleme izniniz olan ağlarda kullanın.")
    print("Yasalara uygun şekilde kullanım sorumluluğu kullanıcıya aittir.")
    print("⚠️" * 20)
    
    # Yetki kontrolü
    if os.geteuid() != 0:
        print("\n❌ Bu araç root yetkileri gerektirir!")
        print("Linux/macOS: sudo python3 shark.py")
        print("Windows: Administrator olarak çalıştırın")
        sys.exit(1)
    
    # Ağ arayüzü belirleme
    interface = args.interface
    if args.auto_interface and not interface:
        # Otomatik tespit
        try:
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
    if args.fast:
        # Hızlı mod - sadece temel özellikler
        advanced_mode = False
        web_activity_mode = False
        print("🚀 Hızlı mod aktif - sadece temel özellikler")
    else:
        advanced_mode = args.advanced or args.topology or args.penetration
        web_activity_mode = args.web_activity or args.advanced
    
    monitor = NetworkMonitor(interface=interface, output_file=args.output, 
                           advanced_mode=advanced_mode, web_activity_mode=web_activity_mode)
    
    try:
        # Ağ bilgilerini al
        network = monitor.get_network_info()
        if not network:
            print("❌ Ağ bilgileri alınamadı")
            sys.exit(1)
        
        # Ağ tarama
        monitor.scan_network(network)
        
        # MAC adresleri
        monitor.get_mac_addresses()
        
        # Gelişmiş cihaz tarama
        device_profiles = None
        if advanced_mode:
            device_profiles = monitor.advanced_device_scanning()
        
        # İzleme başlat
        print(f"\n🚀 {args.duration} saniye boyunca izleme başlatılıyor...")
        print("⏹️  Durdurmak için Ctrl+C kullanın")
        
        monitor_thread = monitor.start_monitoring(duration=args.duration)
        
        # İzleme süresini bekle
        monitor_thread.join()
        
        # Sonuçları kaydet
        monitor.save_pcap()
        monitor.generate_report()
        
        # Gelişmiş analizler
        if advanced_mode and device_profiles:
            # Ağ topolojisi analizi
            if args.topology or args.advanced:
                topology_analysis = monitor.analyze_network_topology(device_profiles)
                if topology_analysis:
                    print(f"\n🌐 Topoloji Analizi:")
                    print(f"   📊 Toplam cihaz: {topology_analysis['total_devices']}")
                    print(f"   🔗 Toplam bağlantı: {topology_analysis['total_connections']}")
                    print(f"   🏥 Ağ sağlığı: {topology_analysis['network_health']['level']}")
            
            # Penetrasyon testleri
            if args.penetration or args.advanced:
                penetration_results = monitor.run_penetration_tests(device_profiles)
                if penetration_results:
                    print(f"\n🔒 Penetrasyon Testleri:")
                    for ip, result in penetration_results.items():
                        print(f"   🎯 {ip}: Risk Skoru {result['risk_score']} - {len(result['vulnerabilities'])} güvenlik açığı")
        
        # Web aktivite ile basit topoloji analizi
        elif args.web_activity and monitor.topology_mapper:
            # Basit cihaz listesi oluştur
            simple_devices = []
            for ip, mac in monitor.ip_to_mac.items():
                simple_devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': monitor.identify_device_type(mac),
                    'category': 'unknown',
                    'device_type': 'unknown',
                    'open_ports': []
                })
            
            if simple_devices:
                topology_analysis = monitor.analyze_network_topology(simple_devices)
                if topology_analysis:
                    print(f"\n🌐 Basit Topoloji Analizi:")
                    print(f"   📊 Toplam cihaz: {topology_analysis['total_devices']}")
                    print(f"   🔗 Toplam bağlantı: {topology_analysis['total_connections']}")
                    print(f"   🏥 Ağ sağlığı: {topology_analysis['network_health']['level']}")
            
        # Web aktivite analizi (her zaman çalıştır)
        if monitor.web_activity_monitor:
            monitor.generate_web_activity_report()
        
        monitor.print_summary()
        
        print(f"\n✅ İzleme tamamlandı!")
        print(f"📁 PCAP dosyası: {args.output}")
        print(f"📊 Rapor dosyası: {args.output.replace('.pcap', '_report.json')}")
        
    except KeyboardInterrupt:
        print("\n⏹️  İzleme kullanıcı tarafından durduruldu")
        monitor.running = False
        monitor.save_pcap()
        monitor.generate_report()
        monitor.print_summary()
        
    except Exception as e:
        logger.error(f"❌ Genel hata: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

