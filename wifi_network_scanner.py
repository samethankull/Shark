#!/usr/bin/env python3
"""
WiFi Ağ Tarayıcı - WiFi Network Scanner
======================================

Bu modül, WiFi ağlarını tespit eder ve analiz eder:
- WiFi ağlarını keşfeder
- WiFi cihazlarını tespit eder
- WiFi güvenlik analizi yapar
- WiFi topolojisi çıkarır

⚠️ UYARI: Bu araç yalnızca eğitim amaçlıdır!
"""

import subprocess
import json
import time
import re
import socket
import struct
from datetime import datetime
from collections import defaultdict, Counter
import threading
import os

class WiFiNetworkScanner:
    """WiFi ağ tarayıcı sınıfı"""
    
    def __init__(self, output_file="wifi_scan_report.json"):
        self.output_file = output_file
        self.wifi_networks = {}
        self.wifi_devices = {}
        self.scan_results = {}
        
        print("📡 WiFi Ağ Tarayıcı başlatıldı")
        print(f"💾 Çıktı dosyası: {self.output_file}")
    
    def scan_wifi_networks(self):
        """WiFi ağlarını tara"""
        print("🔍 WiFi ağları taranıyor...")
        
        try:
            # iwlist komutu ile WiFi ağlarını tara
            result = subprocess.run(['iwlist', 'scan'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                networks = self.parse_iwlist_output(result.stdout)
                self.wifi_networks = networks
                print(f"✅ {len(networks)} WiFi ağı bulundu")
                return networks
            else:
                print("❌ iwlist komutu başarısız")
                return {}
                
        except subprocess.TimeoutExpired:
            print("⏰ WiFi tarama zaman aşımı")
            return {}
        except FileNotFoundError:
            print("❌ iwlist komutu bulunamadı")
            return {}
        except Exception as e:
            print(f"❌ WiFi tarama hatası: {e}")
            return {}
    
    def parse_iwlist_output(self, output):
        """iwlist çıktısını parse et"""
        networks = {}
        current_network = {}
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Yeni ağ başlangıcı
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks[current_network['bssid']] = current_network
                
                # BSSID çıkar
                bssid_match = re.search(r'Address: ([0-9A-Fa-f:]{17})', line)
                if bssid_match:
                    current_network = {
                        'bssid': bssid_match.group(1),
                        'timestamp': datetime.now().isoformat()
                    }
            
            # ESSID (Ağ adı)
            elif 'ESSID:' in line:
                essid_match = re.search(r'ESSID:"([^"]*)"', line)
                if essid_match:
                    current_network['essid'] = essid_match.group(1)
            
            # Sinyal gücü
            elif 'Signal level=' in line:
                signal_match = re.search(r'Signal level=(-?\d+)', line)
                if signal_match:
                    current_network['signal_level'] = int(signal_match.group(1))
            
            # Frekans
            elif 'Frequency:' in line:
                freq_match = re.search(r'Frequency:(\d+\.\d+)', line)
                if freq_match:
                    current_network['frequency'] = float(freq_match.group(1))
            
            # Kanal
            elif 'Channel:' in line:
                channel_match = re.search(r'Channel:(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))
            
            # Şifreleme
            elif 'Encryption key:' in line:
                if 'on' in line:
                    current_network['encrypted'] = True
                else:
                    current_network['encrypted'] = False
            
            # Şifreleme türü
            elif 'IE:' in line:
                if 'WPA' in line:
                    current_network['encryption_type'] = 'WPA'
                elif 'WEP' in line:
                    current_network['encryption_type'] = 'WEP'
                elif 'WPA2' in line:
                    current_network['encryption_type'] = 'WPA2'
                elif 'WPA3' in line:
                    current_network['encryption_type'] = 'WPA3'
        
        # Son ağı ekle
        if current_network:
            networks[current_network['bssid']] = current_network
        
        return networks
    
    def analyze_wifi_security(self, network):
        """WiFi güvenlik analizi"""
        security_score = 100
        vulnerabilities = []
        recommendations = []
        
        # Şifreleme kontrolü
        if not network.get('encrypted', False):
            security_score -= 50
            vulnerabilities.append("Şifreleme yok")
            recommendations.append("WPA2/WPA3 şifreleme kullanın")
        
        # Şifreleme türü kontrolü
        encryption_type = network.get('encryption_type', '')
        if encryption_type == 'WEP':
            security_score -= 30
            vulnerabilities.append("Zayıf WEP şifreleme")
            recommendations.append("WPA2 veya WPA3'e geçin")
        elif encryption_type == 'WPA':
            security_score -= 20
            vulnerabilities.append("Eski WPA şifreleme")
            recommendations.append("WPA2 veya WPA3'e geçin")
        elif encryption_type in ['WPA2', 'WPA3']:
            security_score += 10
            recommendations.append("Güçlü şifreleme kullanılıyor")
        
        # Sinyal gücü kontrolü
        signal_level = network.get('signal_level', -100)
        if signal_level > -30:
            security_score -= 10
            vulnerabilities.append("Çok güçlü sinyal (sızıntı riski)")
            recommendations.append("Sinyal gücünü azaltın")
        
        # Ağ adı kontrolü
        essid = network.get('essid', '')
        if not essid:
            security_score -= 5
            vulnerabilities.append("Gizli ağ (SSID yayını yok)")
            recommendations.append("SSID yayınını açın")
        elif essid.lower() in ['admin', 'default', 'router', 'wifi']:
            security_score -= 15
            vulnerabilities.append("Varsayılan ağ adı")
            recommendations.append("Özel ağ adı kullanın")
        
        # Risk seviyesi belirleme
        if security_score >= 80:
            risk_level = "Düşük"
        elif security_score >= 60:
            risk_level = "Orta"
        elif security_score >= 40:
            risk_level = "Yüksek"
        else:
            risk_level = "Kritik"
        
        return {
            'security_score': max(0, security_score),
            'risk_level': risk_level,
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations
        }
    
    def scan_wifi_devices(self):
        """WiFi cihazlarını tara"""
        print("📱 WiFi cihazları taranıyor...")
        
        devices = {}
        
        try:
            # ARP tablosunu kontrol et
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                devices = self.parse_arp_output(result.stdout)
                print(f"✅ {len(devices)} WiFi cihazı bulundu")
            
        except Exception as e:
            print(f"❌ WiFi cihaz tarama hatası: {e}")
        
        self.wifi_devices = devices
        return devices
    
    def parse_arp_output(self, output):
        """ARP tablosu çıktısını parse et"""
        devices = {}
        
        lines = output.split('\n')
        for line in lines:
            if '(' in line and ')' in line:
                # IP ve MAC adresini çıkar
                ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                mac_match = re.search(r'([0-9A-Fa-f:]{17})', line)
                
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1)
                    
                    # Vendor bilgisini al
                    vendor = self.get_vendor_from_mac(mac)
                    
                    # Cihaz türünü belirle
                    device_type = self.identify_wifi_device_type(mac, vendor)
                    
                    devices[ip] = {
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'device_type': device_type,
                        'connection_type': 'WiFi',
                        'timestamp': datetime.now().isoformat()
                    }
        
        return devices
    
    def get_vendor_from_mac(self, mac):
        """MAC adresinden vendor bilgisi al"""
        oui = mac[:8].upper()
        
        # WiFi vendor veritabanı
        wifi_vendors = {
            '00:1B:21': 'Apple Inc.',
            '00:1C:42': 'Apple Inc.',
            '00:1D:4F': 'Apple Inc.',
            '00:23:12': 'Apple Inc.',
            '00:25:00': 'Apple Inc.',
            '00:26:08': 'Apple Inc.',
            '00:26:4A': 'Apple Inc.',
            '00:26:B0': 'Apple Inc.',
            '00:26:BB': 'Apple Inc.',
            '00:50:56': 'VMware, Inc.',
            '08:00:27': 'Oracle VirtualBox',
            '00:15:B7': 'Cisco Systems',
            '00:16:3E': 'Cisco Systems',
            '00:17:42': 'Cisco Systems',
            '00:0C:29': 'VMware, Inc.',
            '00:0F:4B': 'Cisco Systems',
            '00:11:22': 'Dell Inc.',
            '00:14:22': 'Dell Inc.',
            '00:15:5D': 'Microsoft Corporation',
            '00:16:3E': 'Cisco Systems',
            '00:17:42': 'Cisco Systems',
            '00:18:39': 'Cisco Systems',
            '00:19:07': 'Cisco Systems',
            '00:1A:2F': 'Cisco Systems',
            '00:1B:0D': 'Cisco Systems',
            '00:1C:0E': 'Cisco Systems',
            '00:1D:45': 'Cisco Systems',
            '00:1E:13': 'Cisco Systems',
            '00:1F:26': 'Cisco Systems',
            '00:21:6A': 'Cisco Systems',
            '00:22:55': 'Cisco Systems',
            '00:23:04': 'Cisco Systems',
            '00:24:50': 'Cisco Systems',
            '00:25:45': 'Cisco Systems',
            '00:26:08': 'Cisco Systems',
            '00:26:4A': 'Cisco Systems',
            '00:26:B0': 'Cisco Systems',
            '00:26:BB': 'Cisco Systems',
            '00:27:10': 'Cisco Systems',
            '00:28:45': 'Cisco Systems',
            '00:29:1C': 'Cisco Systems',
            '00:2A:6A': 'Cisco Systems',
            '00:2B:67': 'Cisco Systems',
            '00:2C:54': 'Cisco Systems',
            '00:2D:76': 'Cisco Systems',
            '00:2E:60': 'Cisco Systems',
            '00:2F:74': 'Cisco Systems',
            '00:30:40': 'Cisco Systems',
            '00:31:92': 'Cisco Systems',
            '00:32:58': 'Cisco Systems',
            '00:33:66': 'Cisco Systems',
            '00:34:DA': 'Cisco Systems',
            '00:35:1A': 'Cisco Systems',
            '00:36:76': 'Cisco Systems',
            '00:37:6D': 'Cisco Systems',
            '00:38:DF': 'Cisco Systems',
            '00:39:2B': 'Cisco Systems',
            '00:3A:99': 'Cisco Systems',
            '00:3B:7C': 'Cisco Systems',
            '00:3C:10': 'Cisco Systems',
            '00:3D:41': 'Cisco Systems',
            '00:3E:E1': 'Cisco Systems',
            '00:3F:0D': 'Cisco Systems',
            '00:40:96': 'Cisco Systems',
            '00:41:D2': 'Cisco Systems',
            '00:42:5A': 'Cisco Systems',
            '00:43:60': 'Cisco Systems',
            '00:44:50': 'Cisco Systems',
            '00:45:32': 'Cisco Systems',
            '00:46:65': 'Cisco Systems',
            '00:47:40': 'Cisco Systems',
            '00:48:54': 'Cisco Systems',
            '00:49:3B': 'Cisco Systems',
            '00:4A:77': 'Cisco Systems',
            '00:4B:80': 'Cisco Systems',
            '00:4C:60': 'Cisco Systems',
            '00:4D:32': 'Cisco Systems',
            '00:4E:35': 'Cisco Systems',
            '00:4F:58': 'Cisco Systems',
            '00:50:56': 'Cisco Systems',
            '00:51:56': 'Cisco Systems',
            '00:52:56': 'Cisco Systems',
            '00:53:56': 'Cisco Systems',
            '00:54:56': 'Cisco Systems',
            '00:55:56': 'Cisco Systems',
            '00:56:56': 'Cisco Systems',
            '00:57:56': 'Cisco Systems',
            '00:58:56': 'Cisco Systems',
            '00:59:56': 'Cisco Systems',
            '00:5A:56': 'Cisco Systems',
            '00:5B:56': 'Cisco Systems',
            '00:5C:56': 'Cisco Systems',
            '00:5D:56': 'Cisco Systems',
            '00:5E:56': 'Cisco Systems',
            '00:5F:56': 'Cisco Systems',
            '00:60:56': 'Cisco Systems',
            '00:61:56': 'Cisco Systems',
            '00:62:56': 'Cisco Systems',
            '00:63:56': 'Cisco Systems',
            '00:64:56': 'Cisco Systems',
            '00:65:56': 'Cisco Systems',
            '00:66:56': 'Cisco Systems',
            '00:67:56': 'Cisco Systems',
            '00:68:56': 'Cisco Systems',
            '00:69:56': 'Cisco Systems',
            '00:6A:56': 'Cisco Systems',
            '00:6B:56': 'Cisco Systems',
            '00:6C:56': 'Cisco Systems',
            '00:6D:56': 'Cisco Systems',
            '00:6E:56': 'Cisco Systems',
            '00:6F:56': 'Cisco Systems',
            '00:70:56': 'Cisco Systems',
            '00:71:56': 'Cisco Systems',
            '00:72:56': 'Cisco Systems',
            '00:73:56': 'Cisco Systems',
            '00:74:56': 'Cisco Systems',
            '00:75:56': 'Cisco Systems',
            '00:76:56': 'Cisco Systems',
            '00:77:56': 'Cisco Systems',
            '00:78:56': 'Cisco Systems',
            '00:79:56': 'Cisco Systems',
            '00:7A:56': 'Cisco Systems',
            '00:7B:56': 'Cisco Systems',
            '00:7C:56': 'Cisco Systems',
            '00:7D:56': 'Cisco Systems',
            '00:7E:56': 'Cisco Systems',
            '00:7F:56': 'Cisco Systems',
            '00:80:56': 'Cisco Systems',
            '00:81:56': 'Cisco Systems',
            '00:82:56': 'Cisco Systems',
            '00:83:56': 'Cisco Systems',
            '00:84:56': 'Cisco Systems',
            '00:85:56': 'Cisco Systems',
            '00:86:56': 'Cisco Systems',
            '00:87:56': 'Cisco Systems',
            '00:88:56': 'Cisco Systems',
            '00:89:56': 'Cisco Systems',
            '00:8A:56': 'Cisco Systems',
            '00:8B:56': 'Cisco Systems',
            '00:8C:56': 'Cisco Systems',
            '00:8D:56': 'Cisco Systems',
            '00:8E:56': 'Cisco Systems',
            '00:8F:56': 'Cisco Systems',
            '00:90:56': 'Cisco Systems',
            '00:91:56': 'Cisco Systems',
            '00:92:56': 'Cisco Systems',
            '00:93:56': 'Cisco Systems',
            '00:94:56': 'Cisco Systems',
            '00:95:56': 'Cisco Systems',
            '00:96:56': 'Cisco Systems',
            '00:97:56': 'Cisco Systems',
            '00:98:56': 'Cisco Systems',
            '00:99:56': 'Cisco Systems',
            '00:9A:56': 'Cisco Systems',
            '00:9B:56': 'Cisco Systems',
            '00:9C:56': 'Cisco Systems',
            '00:9D:56': 'Cisco Systems',
            '00:9E:56': 'Cisco Systems',
            '00:9F:56': 'Cisco Systems',
            '00:A0:56': 'Cisco Systems',
            '00:A1:56': 'Cisco Systems',
            '00:A2:56': 'Cisco Systems',
            '00:A3:56': 'Cisco Systems',
            '00:A4:56': 'Cisco Systems',
            '00:A5:56': 'Cisco Systems',
            '00:A6:56': 'Cisco Systems',
            '00:A7:56': 'Cisco Systems',
            '00:A8:56': 'Cisco Systems',
            '00:A9:56': 'Cisco Systems',
            '00:AA:56': 'Cisco Systems',
            '00:AB:56': 'Cisco Systems',
            '00:AC:56': 'Cisco Systems',
            '00:AD:56': 'Cisco Systems',
            '00:AE:56': 'Cisco Systems',
            '00:AF:56': 'Cisco Systems',
            '00:B0:56': 'Cisco Systems',
            '00:B1:56': 'Cisco Systems',
            '00:B2:56': 'Cisco Systems',
            '00:B3:56': 'Cisco Systems',
            '00:B4:56': 'Cisco Systems',
            '00:B5:56': 'Cisco Systems',
            '00:B6:56': 'Cisco Systems',
            '00:B7:56': 'Cisco Systems',
            '00:B8:56': 'Cisco Systems',
            '00:B9:56': 'Cisco Systems',
            '00:BA:56': 'Cisco Systems',
            '00:BB:56': 'Cisco Systems',
            '00:BC:56': 'Cisco Systems',
            '00:BD:56': 'Cisco Systems',
            '00:BE:56': 'Cisco Systems',
            '00:BF:56': 'Cisco Systems',
            '00:C0:56': 'Cisco Systems',
            '00:C1:56': 'Cisco Systems',
            '00:C2:56': 'Cisco Systems',
            '00:C3:56': 'Cisco Systems',
            '00:C4:56': 'Cisco Systems',
            '00:C5:56': 'Cisco Systems',
            '00:C6:56': 'Cisco Systems',
            '00:C7:56': 'Cisco Systems',
            '00:C8:56': 'Cisco Systems',
            '00:C9:56': 'Cisco Systems',
            '00:CA:56': 'Cisco Systems',
            '00:CB:56': 'Cisco Systems',
            '00:CC:56': 'Cisco Systems',
            '00:CD:56': 'Cisco Systems',
            '00:CE:56': 'Cisco Systems',
            '00:CF:56': 'Cisco Systems',
            '00:D0:56': 'Cisco Systems',
            '00:D1:56': 'Cisco Systems',
            '00:D2:56': 'Cisco Systems',
            '00:D3:56': 'Cisco Systems',
            '00:D4:56': 'Cisco Systems',
            '00:D5:56': 'Cisco Systems',
            '00:D6:56': 'Cisco Systems',
            '00:D7:56': 'Cisco Systems',
            '00:D8:56': 'Cisco Systems',
            '00:D9:56': 'Cisco Systems',
            '00:DA:56': 'Cisco Systems',
            '00:DB:56': 'Cisco Systems',
            '00:DC:56': 'Cisco Systems',
            '00:DD:56': 'Cisco Systems',
            '00:DE:56': 'Cisco Systems',
            '00:DF:56': 'Cisco Systems',
            '00:E0:56': 'Cisco Systems',
            '00:E1:56': 'Cisco Systems',
            '00:E2:56': 'Cisco Systems',
            '00:E3:56': 'Cisco Systems',
            '00:E4:56': 'Cisco Systems',
            '00:E5:56': 'Cisco Systems',
            '00:E6:56': 'Cisco Systems',
            '00:E7:56': 'Cisco Systems',
            '00:E8:56': 'Cisco Systems',
            '00:E9:56': 'Cisco Systems',
            '00:EA:56': 'Cisco Systems',
            '00:EB:56': 'Cisco Systems',
            '00:EC:56': 'Cisco Systems',
            '00:ED:56': 'Cisco Systems',
            '00:EE:56': 'Cisco Systems',
            '00:EF:56': 'Cisco Systems',
            '00:F0:56': 'Cisco Systems',
            '00:F1:56': 'Cisco Systems',
            '00:F2:56': 'Cisco Systems',
            '00:F3:56': 'Cisco Systems',
            '00:F4:56': 'Cisco Systems',
            '00:F5:56': 'Cisco Systems',
            '00:F6:56': 'Cisco Systems',
            '00:F7:56': 'Cisco Systems',
            '00:F8:56': 'Cisco Systems',
            '00:F9:56': 'Cisco Systems',
            '00:FA:56': 'Cisco Systems',
            '00:FB:56': 'Cisco Systems',
            '00:FC:56': 'Cisco Systems',
            '00:FD:56': 'Cisco Systems',
            '00:FE:56': 'Cisco Systems',
            '00:FF:56': 'Cisco Systems'
        }
        
        return wifi_vendors.get(oui, 'Unknown Vendor')
    
    def identify_wifi_device_type(self, mac, vendor):
        """WiFi cihaz türünü belirle"""
        # Vendor'a göre cihaz türü
        if 'Apple' in vendor:
            return 'iPhone/iPad/Mac'
        elif 'Cisco' in vendor:
            return 'Router/Switch'
        elif 'Dell' in vendor:
            return 'Laptop/Desktop'
        elif 'Microsoft' in vendor:
            return 'Windows Device'
        elif 'VMware' in vendor:
            return 'Virtual Machine'
        elif 'Oracle' in vendor:
            return 'Virtual Machine'
        else:
            return 'Unknown Device'
    
    def generate_wifi_report(self):
        """WiFi raporu oluştur"""
        print("📊 WiFi raporu oluşturuluyor...")
        
        # Güvenlik analizi yap
        for bssid, network in self.wifi_networks.items():
            security_analysis = self.analyze_wifi_security(network)
            network['security_analysis'] = security_analysis
        
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_networks': len(self.wifi_networks),
                'total_devices': len(self.wifi_devices),
                'scanner': 'WiFi Network Scanner'
            },
            'wifi_networks': self.wifi_networks,
            'wifi_devices': self.wifi_devices,
            'statistics': self.calculate_wifi_statistics()
        }
        
        # Raporu kaydet
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ WiFi raporu kaydedildi: {self.output_file}")
        return report
    
    def calculate_wifi_statistics(self):
        """WiFi istatistiklerini hesapla"""
        stats = {
            'total_networks': len(self.wifi_networks),
            'total_devices': len(self.wifi_devices),
            'encrypted_networks': 0,
            'unencrypted_networks': 0,
            'encryption_types': Counter(),
            'device_types': Counter(),
            'vendors': Counter(),
            'channels': Counter(),
            'security_risks': Counter()
        }
        
        # Ağ istatistikleri
        for network in self.wifi_networks.values():
            if network.get('encrypted', False):
                stats['encrypted_networks'] += 1
            else:
                stats['unencrypted_networks'] += 1
            
            encryption_type = network.get('encryption_type', 'Unknown')
            stats['encryption_types'][encryption_type] += 1
            
            channel = network.get('channel', 0)
            stats['channels'][channel] += 1
            
            risk_level = network.get('security_analysis', {}).get('risk_level', 'Unknown')
            stats['security_risks'][risk_level] += 1
        
        # Cihaz istatistikleri
        for device in self.wifi_devices.values():
            device_type = device.get('device_type', 'Unknown')
            stats['device_types'][device_type] += 1
            
            vendor = device.get('vendor', 'Unknown')
            stats['vendors'][vendor] += 1
        
        return dict(stats)
    
    def print_wifi_summary(self):
        """WiFi özetini yazdır"""
        print("\n" + "="*60)
        print("📡 WİFİ AĞ TARAMA ÖZETİ")
        print("="*60)
        
        print(f"📶 Toplam WiFi Ağı: {len(self.wifi_networks)}")
        print(f"📱 Toplam WiFi Cihazı: {len(self.wifi_devices)}")
        
        # Şifreleme istatistikleri
        encrypted = sum(1 for n in self.wifi_networks.values() if n.get('encrypted', False))
        unencrypted = len(self.wifi_networks) - encrypted
        
        print(f"\n🔒 Şifreleme Durumu:")
        print(f"   Şifreli: {encrypted}")
        print(f"   Şifresiz: {unencrypted}")
        
        # Şifreleme türleri
        print(f"\n🔐 Şifreleme Türleri:")
        encryption_types = Counter(n.get('encryption_type', 'Unknown') for n in self.wifi_networks.values())
        for enc_type, count in encryption_types.items():
            print(f"   {enc_type}: {count}")
        
        # Cihaz türleri
        print(f"\n📱 Cihaz Türleri:")
        device_types = Counter(d.get('device_type', 'Unknown') for d in self.wifi_devices.values())
        for device_type, count in device_types.items():
            print(f"   {device_type}: {count}")
        
        # Güvenlik riskleri
        print(f"\n⚠️ Güvenlik Riskleri:")
        risk_levels = Counter(n.get('security_analysis', {}).get('risk_level', 'Unknown') for n in self.wifi_networks.values())
        for risk, count in risk_levels.items():
            print(f"   {risk}: {count}")
        
        print("="*60)


def main():
    """Ana fonksiyon"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="WiFi Ağ Tarayıcı - WiFi Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 wifi_network_scanner.py
  sudo python3 wifi_network_scanner.py --output wifi_report.json
  sudo python3 wifi_network_scanner.py --verbose

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
        """
    )
    
    parser.add_argument('--output', '-o', default='wifi_scan_report.json',
                       help='Çıktı dosyası (varsayılan: wifi_scan_report.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    print("📡 WiFi Ağ Tarayıcı - WiFi Network Scanner")
    print("=" * 50)
    print("⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!")
    print("   Yalnızca kendi sahip olduğunuz ağlarda kullanın.")
    print("=" * 50)
    
    # WiFi tarayıcısını oluştur
    scanner = WiFiNetworkScanner(args.output)
    
    try:
        # WiFi ağlarını tara
        networks = scanner.scan_wifi_networks()
        
        # WiFi cihazlarını tara
        devices = scanner.scan_wifi_devices()
        
        # Rapor oluştur
        report = scanner.generate_wifi_report()
        
        # Özet yazdır
        scanner.print_wifi_summary()
        
        print(f"\n✅ WiFi tarama tamamlandı!")
        print(f"📊 Rapor: {args.output}")
        
    except KeyboardInterrupt:
        print("\n⏹️ Tarama kullanıcı tarafından durduruldu")
    except Exception as e:
        print(f"❌ WiFi tarama hatası: {e}")


if __name__ == "__main__":
    main()



