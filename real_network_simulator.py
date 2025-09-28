#!/usr/bin/env python3
"""
Gerçek Ağ Simülatörü - Real Network Emulator
============================================

Bu modül, gerçek ağ paketleri göndererek simülasyon yapar:
- Gerçek DNS sorguları gönderir
- Gerçek HTTP istekleri gönderir
- Gerçek IoT protokol paketleri gönderir
- Gerçek saldırı paketleri gönderir (eğitim amaçlı)

⚠️ UYARI: Bu araç yalnızca eğitim ve test amaçlıdır!
"""

import json
import time
import random
import threading
import socket
import struct
from datetime import datetime, timedelta
from collections import defaultdict, deque
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.l2 import Ether, ARP
import ipaddress
import requests

class RealNetworkSimulator:
    """Gerçek ağ simülatörü sınıfı"""
    
    def __init__(self, config_file="simulation_config.json"):
        self.config = self.load_config(config_file)
        self.simulated_devices = {}
        self.traffic_patterns = defaultdict(list)
        self.network_topology = {}
        self.running = False
        self.simulation_threads = []
        self.packet_count = 0
        
        # Gerçek ağ verilerini analiz etmek için
        self.real_network_analyzer = None
        
        # Ağ arayüzü
        self.interface = self.get_default_interface()
        
        print("🎭 Gerçek Ağ Simülatörü başlatıldı")
        print(f"📊 Konfigürasyon: {config_file}")
        print(f"🌐 Ağ Arayüzü: {self.interface}")
    
    def get_default_interface(self):
        """Varsayılan ağ arayüzünü bul"""
        try:
            # Sistem varsayılan arayüzünü bul
            import subprocess
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'default via' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            return parts[4]
        except:
            pass
        
        # Fallback: scapy ile bul
        try:
            return conf.iface
        except:
            return "eth0"  # Son çare
    
    def load_config(self, config_file):
        """Simülasyon konfigürasyonunu yükle"""
        default_config = {
            "simulation": {
                "duration": 3600,
                "device_count": 20,
                "traffic_intensity": "medium",
                "network_range": "192.168.100.0/24",
                "simulate_web_traffic": True,
                "simulate_iot_devices": True,
                "simulate_attacks": False,
                "real_packets": True
            },
            "devices": {
                "computers": 0.4,
                "mobiles": 0.3,
                "iot_devices": 0.2,
                "servers": 0.1
            },
            "traffic": {
                "dns_queries_per_minute": 50,
                "http_requests_per_minute": 30,
                "https_connections_per_minute": 20,
                "file_downloads_per_hour": 10
            },
            "attack_simulation": {
                "port_scan_attempts": 5,
                "brute_force_attempts": 3,
                "ddos_attempts": 2
            }
        }
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # Varsayılan değerlerle birleştir
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            print(f"⚠️ Konfigürasyon dosyası bulunamadı: {config_file}")
            print("📝 Varsayılan konfigürasyon kullanılıyor")
            return default_config
    
    def create_simulated_devices(self, real_data=None):
        """Simüle edilecek cihazları oluştur"""
        print("📱 Simüle edilecek cihazlar oluşturuluyor...")
        
        device_count = self.config['simulation']['device_count']
        network_range = self.config['simulation']['network_range']
        
        # Ağ aralığını parse et
        network = ipaddress.ip_network(network_range)
        available_ips = list(network.hosts())
        
        # Cihaz türleri
        device_types = self.config['devices']
        
        for i in range(device_count):
            if i >= len(available_ips):
                break
                
            ip = str(available_ips[i])
            
            # Cihaz türünü belirle
            device_type = self.select_device_type(device_types)
            
            # MAC adresi oluştur
            mac = self.generate_mac_address(device_type)
            
            # Cihaz profili oluştur
            device = {
                'ip': ip,
                'mac': mac,
                'device_type': device_type,
                'vendor': self.get_vendor_from_mac(mac),
                'os': self.get_os_for_device_type(device_type),
                'open_ports': self.get_ports_for_device_type(device_type),
                'traffic_pattern': self.get_traffic_pattern(device_type),
                'last_seen': datetime.now(),
                'is_active': True
            }
            
            # Gerçek verilerden öğrenilen davranışları ekle
            if real_data and real_data.get('devices'):
                self.apply_real_behavior(device, real_data['devices'])
            
            self.simulated_devices[ip] = device
        
        print(f"✅ {len(self.simulated_devices)} cihaz oluşturuldu")
    
    def select_device_type(self, device_types):
        """Cihaz türünü olasılığa göre seç"""
        rand = random.random()
        cumulative = 0
        
        for device_type, probability in device_types.items():
            cumulative += probability
            if rand <= cumulative:
                return device_type
        
        return 'computers'
    
    def generate_mac_address(self, device_type):
        """Cihaz türüne göre MAC adresi oluştur"""
        oui_map = {
            'computers': ['00:1B:21', '00:50:56', '08:00:27'],
            'mobiles': ['00:1B:44', '00:1C:42', '00:1D:4F'],
            'iot_devices': ['00:15:B7', '00:16:3E', '00:17:42'],
            'servers': ['00:0C:29', '00:0F:4B', '00:11:22']
        }
        
        oui = random.choice(oui_map.get(device_type, oui_map['computers']))
        mac_suffix = ':'.join([f"{random.randint(0, 255):02X}" for _ in range(3)])
        
        return f"{oui}:{mac_suffix}"
    
    def get_vendor_from_mac(self, mac):
        """MAC adresinden vendor bilgisi al"""
        oui = mac[:8].upper()
        
        oui_database = {
            '00:1B:21': 'Apple Inc.',
            '00:50:56': 'VMware, Inc.',
            '08:00:27': 'Oracle VirtualBox',
            '00:1B:44': 'Apple Inc.',
            '00:1C:42': 'Apple Inc.',
            '00:15:B7': 'Cisco Systems',
            '00:16:3E': 'Cisco Systems',
            '00:0C:29': 'VMware, Inc.',
            '00:0F:4B': 'Cisco Systems',
            '00:11:22': 'Dell Inc.'
        }
        
        return oui_database.get(oui, 'Unknown Vendor')
    
    def get_os_for_device_type(self, device_type):
        """Cihaz türüne göre işletim sistemi"""
        os_map = {
            'computers': ['Windows 10', 'Windows 11', 'macOS 13.0', 'Ubuntu 22.04'],
            'mobiles': ['iOS 16.0', 'Android 13', 'Android 12'],
            'iot_devices': ['Embedded Linux', 'FreeRTOS', 'Custom Firmware'],
            'servers': ['Ubuntu Server 22.04', 'CentOS 8', 'Windows Server 2022']
        }
        
        return random.choice(os_map.get(device_type, os_map['computers']))
    
    def get_ports_for_device_type(self, device_type):
        """Cihaz türüne göre açık portlar"""
        port_map = {
            'computers': [
                {'port': 22, 'service': 'ssh'},
                {'port': 80, 'service': 'http'},
                {'port': 443, 'service': 'https'},
                {'port': 3389, 'service': 'rdp'}
            ],
            'mobiles': [
                {'port': 443, 'service': 'https'},
                {'port': 80, 'service': 'http'}
            ],
            'iot_devices': [
                {'port': 80, 'service': 'http'},
                {'port': 443, 'service': 'https'},
                {'port': 1883, 'service': 'mqtt'},
                {'port': 5683, 'service': 'coap'}
            ],
            'servers': [
                {'port': 22, 'service': 'ssh'},
                {'port': 80, 'service': 'http'},
                {'port': 443, 'service': 'https'},
                {'port': 21, 'service': 'ftp'},
                {'port': 25, 'service': 'smtp'},
                {'port': 53, 'service': 'dns'}
            ]
        }
        
        ports = port_map.get(device_type, port_map['computers'])
        return random.sample(ports, random.randint(1, len(ports)))
    
    def get_traffic_pattern(self, device_type):
        """Cihaz türüne göre trafik deseni"""
        patterns = {
            'computers': {
                'dns_queries_per_hour': 100,
                'http_requests_per_hour': 200,
                'file_downloads_per_hour': 5,
                'active_hours': [9, 10, 11, 14, 15, 16, 17, 18, 19, 20, 21]
            },
            'mobiles': {
                'dns_queries_per_hour': 150,
                'http_requests_per_hour': 300,
                'file_downloads_per_hour': 10,
                'active_hours': list(range(24))
            },
            'iot_devices': {
                'dns_queries_per_hour': 20,
                'http_requests_per_hour': 50,
                'file_downloads_per_hour': 1,
                'active_hours': list(range(24))
            },
            'servers': {
                'dns_queries_per_hour': 500,
                'http_requests_per_hour': 1000,
                'file_downloads_per_hour': 20,
                'active_hours': list(range(24))
            }
        }
        
        return patterns.get(device_type, patterns['computers'])
    
    def apply_real_behavior(self, device, real_devices):
        """Gerçek cihaz davranışlarını simüle edilen cihaza uygula"""
        similar_devices = [d for d in real_devices if d.get('device_type') == device['device_type']]
        
        if similar_devices:
            real_device = random.choice(similar_devices)
            
            if 'traffic_pattern' in real_device:
                device['traffic_pattern'].update(real_device['traffic_pattern'])
            
            if 'open_ports' in real_device:
                device['open_ports'] = real_device['open_ports']
    
    def start_simulation(self, real_network_range=None):
        """Simülasyonu başlat"""
        print("🚀 Gerçek ağ simülasyonu başlatılıyor...")
        
        # Gerçek ağ analizi (isteğe bağlı)
        real_data = None
        if real_network_range:
            real_data = self.analyze_real_network(real_network_range)
        
        # Simüle edilecek cihazları oluştur
        self.create_simulated_devices(real_data)
        
        # Simülasyon thread'lerini başlat
        self.running = True
        
        # DNS trafiği simülasyonu
        dns_thread = threading.Thread(target=self.simulate_dns_traffic)
        dns_thread.daemon = True
        dns_thread.start()
        self.simulation_threads.append(dns_thread)
        
        # HTTP trafiği simülasyonu
        http_thread = threading.Thread(target=self.simulate_http_traffic)
        http_thread.daemon = True
        http_thread.start()
        self.simulation_threads.append(http_thread)
        
        # IoT cihaz trafiği simülasyonu
        iot_thread = threading.Thread(target=self.simulate_iot_traffic)
        iot_thread.daemon = True
        iot_thread.start()
        self.simulation_threads.append(iot_thread)
        
        # Saldırı simülasyonu (isteğe bağlı)
        if self.config['simulation']['simulate_attacks']:
            attack_thread = threading.Thread(target=self.simulate_attacks)
            attack_thread.daemon = True
            attack_thread.start()
            self.simulation_threads.append(attack_thread)
        
        print("✅ Gerçek simülasyon başlatıldı")
        print(f"📊 {len(self.simulated_devices)} cihaz simüle ediliyor")
        print(f"⏱️ Süre: {self.config['simulation']['duration']} saniye")
    
    def analyze_real_network(self, network_range="192.168.1.0/24", duration=300):
        """Gerçek ağı analiz et ve verileri topla"""
        print("🔍 Gerçek ağ analizi başlatılıyor...")
        
        try:
            from real_network_scanner import RealNetworkScanner
            scanner = RealNetworkScanner()
            devices = scanner.scan_network(network_range)
            
            from real_topology_mapper import RealTopologyMapper
            mapper = RealTopologyMapper()
            topology = mapper.analyze_network_topology(network_range)
            
            from real_time_web_monitor import RealTimeWebMonitor
            monitor = RealTimeWebMonitor()
            monitor.start_monitoring("auto", duration)
            
            print("✅ Gerçek ağ analizi tamamlandı")
            return {
                'devices': devices,
                'topology': topology,
                'web_activity': monitor.get_activity_data()
            }
            
        except Exception as e:
            print(f"❌ Gerçek ağ analizi hatası: {e}")
            return None
    
    def simulate_dns_traffic(self):
        """Gerçek DNS trafiğini simüle et"""
        print("🌐 Gerçek DNS trafiği simülasyonu başlatıldı")
        
        common_domains = [
            'google.com', 'facebook.com', 'youtube.com', 'twitter.com',
            'instagram.com', 'netflix.com', 'amazon.com', 'github.com',
            'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'cnn.com',
            'bbc.com', 'yahoo.com', 'bing.com', 'linkedin.com'
        ]
        
        while self.running:
            for device_ip, device in self.simulated_devices.items():
                if not device['is_active']:
                    continue
                
                current_hour = datetime.now().hour
                if current_hour not in device['traffic_pattern']['active_hours']:
                    continue
                
                if random.random() < 0.1:
                    domain = random.choice(common_domains)
                    self.send_real_dns_query(device_ip, domain)
            
            time.sleep(1)
    
    def simulate_http_traffic(self):
        """Gerçek HTTP trafiğini simüle et"""
        print("🌍 Gerçek HTTP trafiği simülasyonu başlatıldı")
        
        while self.running:
            for device_ip, device in self.simulated_devices.items():
                if not device['is_active']:
                    continue
                
                current_hour = datetime.now().hour
                if current_hour not in device['traffic_pattern']['active_hours']:
                    continue
                
                if random.random() < 0.05:
                    self.send_real_http_request(device_ip)
            
            time.sleep(2)
    
    def simulate_iot_traffic(self):
        """Gerçek IoT cihaz trafiğini simüle et"""
        print("🏠 Gerçek IoT cihaz trafiği simülasyonu başlatıldı")
        
        while self.running:
            for device_ip, device in self.simulated_devices.items():
                if device['device_type'] != 'iot_devices' or not device['is_active']:
                    continue
                
                if random.random() < 0.2:
                    self.send_real_iot_data(device_ip, device)
            
            time.sleep(5)
    
    def simulate_attacks(self):
        """Gerçek saldırı simülasyonu (eğitim amaçlı)"""
        print("⚠️ Gerçek saldırı simülasyonu başlatıldı (eğitim amaçlı)")
        
        while self.running:
            if random.random() < 0.01:
                self.simulate_real_port_scan()
            
            if random.random() < 0.005:
                self.simulate_real_brute_force()
            
            time.sleep(10)
    
    def send_real_dns_query(self, src_ip, domain):
        """Gerçek DNS sorgusu gönder"""
        try:
            # Gerçek DNS sorgu paketi oluştur
            dns_query = DNS(rd=1, qd=DNSQR(qname=domain))
            packet = IP(src=src_ip, dst="8.8.8.8") / UDP(dport=53) / dns_query
            
            # Gerçek paketi gönder
            send(packet, verbose=0)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"🌐 [{timestamp}] GERÇEK DNS: {src_ip} -> {domain}")
            
            self.packet_count += 1
            
            # Trafik desenini kaydet
            self.traffic_patterns[src_ip].append({
                'type': 'real_dns_query',
                'domain': domain,
                'timestamp': timestamp,
                'packet_sent': True
            })
            
        except Exception as e:
            print(f"❌ Gerçek DNS sorgu hatası: {e}")
    
    def send_real_http_request(self, src_ip):
        """Gerçek HTTP isteği gönder"""
        try:
            # Gerçek HTTP isteği paketi oluştur
            http_request = HTTPRequest(
                Host="httpbin.org",
                User_Agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            packet = IP(src=src_ip, dst="54.166.163.67") / TCP(dport=80) / http_request
            
            # Gerçek paketi gönder
            send(packet, verbose=0)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"🌍 [{timestamp}] GERÇEK HTTP: {src_ip} -> httpbin.org")
            
            self.packet_count += 1
            
            # Trafik desenini kaydet
            self.traffic_patterns[src_ip].append({
                'type': 'real_http_request',
                'host': 'httpbin.org',
                'timestamp': timestamp,
                'packet_sent': True
            })
            
        except Exception as e:
            print(f"❌ Gerçek HTTP istek hatası: {e}")
    
    def send_real_iot_data(self, src_ip, device):
        """Gerçek IoT cihaz verisi gönder"""
        try:
            # IoT protokolü simüle et (MQTT benzeri)
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            data_types = {
                'sensor': ['temperature', 'humidity', 'pressure'],
                'camera': ['motion_detected', 'image_captured'],
                'smart_home': ['light_on', 'door_opened', 'alarm_triggered']
            }
            
            device_category = random.choice(list(data_types.keys()))
            data_type = random.choice(data_types[device_category])
            
            # MQTT benzeri paket oluştur
            mqtt_packet = IP(src=src_ip, dst="192.168.100.1") / UDP(dport=1883) / Raw(load=f"MQTT_DATA:{data_type}:{random.uniform(20, 30):.1f}")
            
            # Gerçek paketi gönder
            send(mqtt_packet, verbose=0)
            
            print(f"🏠 [{timestamp}] GERÇEK IoT: {src_ip} -> {data_type}")
            
            self.packet_count += 1
            
            # Trafik desenini kaydet
            self.traffic_patterns[src_ip].append({
                'type': 'real_iot_data',
                'data_type': data_type,
                'device_category': device_category,
                'timestamp': timestamp,
                'packet_sent': True
            })
            
        except Exception as e:
            print(f"❌ Gerçek IoT veri hatası: {e}")
    
    def simulate_real_port_scan(self):
        """Gerçek port tarama simülasyonu"""
        try:
            target_ip = random.choice(list(self.simulated_devices.keys()))
            ports_to_scan = random.sample(range(1, 1024), 10)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"🔍 [{timestamp}] GERÇEK Port Tarama: {target_ip} -> {ports_to_scan}")
            
            # Gerçek SYN paketleri gönder
            for port in ports_to_scan:
                syn_packet = IP(src="192.168.100.254", dst=target_ip) / TCP(dport=port, flags="S")
                send(syn_packet, verbose=0)
                self.packet_count += 1
                time.sleep(0.1)  # Rate limiting
            
            # Saldırı desenini kaydet
            self.traffic_patterns['attacker'].append({
                'type': 'real_port_scan',
                'target': target_ip,
                'ports': ports_to_scan,
                'timestamp': timestamp,
                'packets_sent': len(ports_to_scan)
            })
            
        except Exception as e:
            print(f"❌ Gerçek port tarama hatası: {e}")
    
    def simulate_real_brute_force(self):
        """Gerçek brute force saldırısı simülasyonu"""
        try:
            target_ip = random.choice(list(self.simulated_devices.keys()))
            
            usernames = ['admin', 'root', 'user', 'guest']
            passwords = ['123456', 'password', 'admin', '12345']
            
            username = random.choice(usernames)
            password = random.choice(passwords)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"🔐 [{timestamp}] GERÇEK Brute Force: {target_ip} -> {username}:{password}")
            
            # Gerçek SSH bağlantı denemesi paketi
            ssh_packet = IP(src="192.168.100.254", dst=target_ip) / TCP(dport=22, flags="S")
            send(ssh_packet, verbose=0)
            self.packet_count += 1
            
            # Saldırı desenini kaydet
            self.traffic_patterns['attacker'].append({
                'type': 'real_brute_force',
                'target': target_ip,
                'username': username,
                'password': password,
                'timestamp': timestamp,
                'packet_sent': True
            })
            
        except Exception as e:
            print(f"❌ Gerçek brute force hatası: {e}")
    
    def stop_simulation(self):
        """Simülasyonu durdur"""
        print("⏹️ Gerçek simülasyon durduruluyor...")
        self.running = False
        
        for thread in self.simulation_threads:
            thread.join(timeout=5)
        
        print("✅ Gerçek simülasyon durduruldu")
        print(f"📊 Toplam gönderilen paket: {self.packet_count}")
    
    def generate_simulation_report(self, output_file="real_simulation_report.json"):
        """Simülasyon raporu oluştur"""
        print("📊 Gerçek simülasyon raporu oluşturuluyor...")
        
        report = {
            'simulation_info': {
                'start_time': datetime.now().isoformat(),
                'duration': self.config['simulation']['duration'],
                'device_count': len(self.simulated_devices),
                'network_range': self.config['simulation']['network_range'],
                'total_packets_sent': self.packet_count,
                'real_packets': True
            },
            'simulated_devices': self.simulated_devices,
            'traffic_patterns': dict(self.traffic_patterns),
            'statistics': self.calculate_statistics()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Gerçek simülasyon raporu kaydedildi: {output_file}")
        return report
    
    def calculate_statistics(self):
        """Simülasyon istatistiklerini hesapla"""
        stats = {
            'total_devices': len(self.simulated_devices),
            'device_types': defaultdict(int),
            'total_traffic_events': 0,
            'traffic_by_type': defaultdict(int),
            'active_devices': 0,
            'real_packets_sent': self.packet_count
        }
        
        for device in self.simulated_devices.values():
            stats['device_types'][device['device_type']] += 1
            if device['is_active']:
                stats['active_devices'] += 1
        
        for ip, events in self.traffic_patterns.items():
            stats['total_traffic_events'] += len(events)
            for event in events:
                stats['traffic_by_type'][event['type']] += 1
        
        return dict(stats)
    
    def print_simulation_summary(self):
        """Simülasyon özetini yazdır"""
        print("\n" + "="*60)
        print("🎭 GERÇEK AĞ SİMÜLASYONU ÖZETİ")
        print("="*60)
        
        print(f"📱 Toplam Cihaz: {len(self.simulated_devices)}")
        print(f"🌐 Ağ Aralığı: {self.config['simulation']['network_range']}")
        print(f"⏱️ Simülasyon Süresi: {self.config['simulation']['duration']} saniye")
        print(f"📦 Toplam Gönderilen Paket: {self.packet_count}")
        
        # Cihaz türü dağılımı
        print("\n📊 Cihaz Türü Dağılımı:")
        device_types = defaultdict(int)
        for device in self.simulated_devices.values():
            device_types[device['device_type']] += 1
        
        for device_type, count in device_types.items():
            percentage = (count / len(self.simulated_devices)) * 100
            print(f"   {device_type}: {count} (%{percentage:.1f})")
        
        # Trafik istatistikleri
        print("\n🌐 Gerçek Trafik İstatistikleri:")
        total_events = sum(len(events) for events in self.traffic_patterns.values())
        print(f"   Toplam Trafik Olayı: {total_events}")
        print(f"   Gerçek Paket Gönderildi: {self.packet_count}")
        
        traffic_by_type = defaultdict(int)
        for events in self.traffic_patterns.values():
            for event in events:
                traffic_by_type[event['type']] += 1
        
        for event_type, count in traffic_by_type.items():
            print(f"   {event_type}: {count}")
        
        print("="*60)


def main():
    """Ana fonksiyon"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Gerçek Ağ Simülatörü - Real Network Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 real_network_simulator.py --config simulation_config.json
  sudo python3 real_network_simulator.py --analyze-real 192.168.1.0/24
  sudo python3 real_network_simulator.py --duration 1800 --devices 50

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
   Gerçek paketler gönderir - dikkatli kullanın!
        """
    )
    
    parser.add_argument('--config', '-c', default='simulation_config.json',
                       help='Simülasyon konfigürasyon dosyası')
    parser.add_argument('--analyze-real', '-a', 
                       help='Gerçek ağı analiz et (örn: 192.168.1.0/24)')
    parser.add_argument('--duration', '-d', type=int,
                       help='Simülasyon süresi (saniye)')
    parser.add_argument('--devices', '-n', type=int,
                       help='Simüle edilecek cihaz sayısı')
    parser.add_argument('--output', '-o', default='real_simulation_report.json',
                       help='Çıktı dosyası')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    print("🎭 Gerçek Ağ Simülatörü - Real Network Emulator")
    print("=" * 60)
    print("⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!")
    print("   GERÇEK PAKETLER GÖNDERİR - dikkatli kullanın!")
    print("   Yalnızca test ortamlarında kullanın.")
    print("=" * 60)
    
    # Simülatörü oluştur
    simulator = RealNetworkSimulator(args.config)
    
    # Komut satırı parametrelerini uygula
    if args.duration:
        simulator.config['simulation']['duration'] = args.duration
    if args.devices:
        simulator.config['simulation']['device_count'] = args.devices
    
    try:
        # Simülasyonu başlat
        simulator.start_simulation(args.analyze_real)
        
        # Simülasyon süresini bekle
        duration = simulator.config['simulation']['duration']
        print(f"⏱️ Simülasyon {duration} saniye çalışacak...")
        
        time.sleep(duration)
        
        # Simülasyonu durdur
        simulator.stop_simulation()
        
        # Rapor oluştur
        report = simulator.generate_simulation_report(args.output)
        
        # Özet yazdır
        simulator.print_simulation_summary()
        
        print(f"\n✅ Gerçek simülasyon tamamlandı!")
        print(f"📊 Rapor: {args.output}")
        
    except KeyboardInterrupt:
        print("\n⏹️ Simülasyon kullanıcı tarafından durduruldu")
        simulator.stop_simulation()
    except Exception as e:
        print(f"❌ Simülasyon hatası: {e}")
        simulator.stop_simulation()


if __name__ == "__main__":
    main()



