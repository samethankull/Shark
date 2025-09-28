#!/usr/bin/env python3
"""
Gerçek Ağ Topolojisi Çıkarıcı
==============================

Bu modül, gerçek ağ trafiğini analiz ederek topoloji oluşturur.
"""

import sys
import os
import time
import json
import subprocess
import re
import threading
from collections import defaultdict, Counter
import networkx as nx
import matplotlib.pyplot as plt
from real_network_scanner import RealNetworkScanner

class RealTopologyMapper:
    """Gerçek ağ topolojisi çıkarıcı sınıfı"""
    
    def __init__(self, network_range=None, output_file="real_topology.json"):
        self.network_range = network_range
        self.output_file = output_file
        self.topology_graph = nx.Graph()
        self.device_connections = defaultdict(set)
        self.traffic_data = []
        self.devices = {}
        
        print(f"🌐 Gerçek Ağ Topolojisi Çıkarıcı başlatıldı")
        print(f"🌐 Ağ aralığı: {self.network_range}")
        print(f"💾 Çıktı dosyası: {self.output_file}")
    
    def scan_network_devices(self):
        """Ağ cihazlarını tara"""
        print(f"🔍 Ağ cihazları taranıyor...")
        
        # Gerçek ağ tarayıcısını kullan
        scanner = RealNetworkScanner(network_range=self.network_range)
        scan_results = scanner.scan_network()
        
        # Cihaz listesini hazırla
        devices = []
        for ip, profile in scan_results.items():
            device = {
                'ip': ip,
                'mac': profile['mac'],
                'vendor': profile['vendor'],
                'category': profile['category'],
                'device_type': profile['category'],
                'open_ports': profile.get('real_scan', {}).get('open_ports', []),
                'os_info': profile.get('real_scan', {}).get('os_info', {}),
                'risk_level': profile['risk_level']
            }
            devices.append(device)
            self.devices[ip] = device
        
        print(f"📊 {len(devices)} cihaz bulundu")
        return devices
    
    def discover_network_connections(self):
        """Ağ bağlantılarını keşfet"""
        print(f"🔗 Ağ bağlantıları keşfediliyor...")
        
        # ARP tablosunu analiz et
        self.analyze_arp_table()
        
        # Routing tablosunu analiz et
        self.analyze_routing_table()
        
        # Traceroute ile bağlantıları keşfet
        self.analyze_traceroutes()
        
        # Ping ile bağlantıları test et
        self.analyze_ping_connectivity()
    
    def analyze_arp_table(self):
        """ARP tablosunu analiz et"""
        print(f"🔍 ARP tablosu analiz ediliyor...")
        
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'dynamic' in line or 'static' in line:
                        # IP ve MAC adreslerini çıkar
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line)
                        
                        if ip_match and mac_match:
                            ip = ip_match.group(1)
                            mac = mac_match.group(1)
                            
                            # Cihazı grafiğe ekle
                            if ip in self.devices:
                                self.topology_graph.add_node(ip, 
                                                           mac=mac,
                                                           vendor=self.devices[ip]['vendor'],
                                                           category=self.devices[ip]['category'],
                                                           device_type=self.devices[ip]['device_type'])
                                
        except Exception as e:
            print(f"⚠️ ARP tablosu analizi hatası: {e}")
    
    def analyze_routing_table(self):
        """Routing tablosunu analiz et"""
        print(f"🔍 Routing tablosu analiz ediliyor...")
        
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'default' in line:
                        # Gateway'i bul
                        gateway_match = re.search(r'via (\d+\.\d+\.\d+\.\d+)', line)
                        if gateway_match:
                            gateway = gateway_match.group(1)
                            
                            # Gateway'i router olarak işaretle
                            if gateway in self.devices:
                                self.devices[gateway]['category'] = 'router'
                                self.devices[gateway]['device_type'] = 'router'
                                
        except Exception as e:
            print(f"⚠️ Routing tablosu analizi hatası: {e}")
    
    def analyze_traceroutes(self):
        """Traceroute ile bağlantıları analiz et"""
        print(f"🔍 Traceroute analizi yapılıyor...")
        
        # Her cihaz için traceroute yap
        for ip in self.devices.keys():
            try:
                result = subprocess.run(['traceroute', '-n', ip], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    prev_ip = None
                    
                    for line in lines[1:]:  # İlk satırı atla
                        if line.strip():
                            # IP adresini çıkar
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                current_ip = ip_match.group(1)
                                
                                # Bağlantıyı grafiğe ekle
                                if prev_ip and current_ip != prev_ip:
                                    self.topology_graph.add_edge(prev_ip, current_ip)
                                    self.device_connections[prev_ip].add(current_ip)
                                    self.device_connections[current_ip].add(prev_ip)
                                
                                prev_ip = current_ip
                                
            except Exception as e:
                print(f"⚠️ Traceroute hatası {ip}: {e}")
    
    def analyze_ping_connectivity(self):
        """Ping ile bağlantıları test et"""
        print(f"🔍 Ping bağlantı testleri yapılıyor...")
        
        # Her cihaz çifti için ping testi
        device_ips = list(self.devices.keys())
        for i, ip1 in enumerate(device_ips):
            for ip2 in device_ips[i+1:]:
                try:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', ip2], 
                                          capture_output=True, text=True, timeout=3)
                    if result.returncode == 0:
                        # Bağlantı var, grafiğe ekle
                        self.topology_graph.add_edge(ip1, ip2)
                        self.device_connections[ip1].add(ip2)
                        self.device_connections[ip2].add(ip1)
                        
                except Exception as e:
                    pass  # Ping başarısız, bağlantı yok
    
    def identify_network_devices(self):
        """Ağ cihazlarını tanımla"""
        print(f"🔍 Ağ cihazları tanımlanıyor...")
        
        switches = []
        routers = []
        access_points = []
        
        for ip, device in self.devices.items():
            vendor = device['vendor'].lower()
            category = device['category'].lower()
            open_ports = device['open_ports']
            
            # Switch tespiti
            is_switch = False
            if any(switch_vendor in vendor for switch_vendor in 
                   ['cisco', 'netgear', 'linksys', 'tp-link', 'd-link', 'asus', 'belkin']):
                if category in ['router', 'switch', 'access_point']:
                    is_switch = True
            
            # Port bazlı tespit
            for port_info in open_ports:
                port = port_info['port']
                if port == 161 or port == 162:  # SNMP
                    is_switch = True
                elif port == 23:  # Telnet
                    is_switch = True
                elif port == 22:  # SSH
                    is_switch = True
            
            if is_switch:
                switches.append({
                    'ip': ip,
                    'mac': device['mac'],
                    'vendor': device['vendor'],
                    'category': 'switch',
                    'ports': open_ports
                })
            
            # Router tespiti
            is_router = False
            if any(router_vendor in vendor for router_vendor in 
                   ['cisco', 'netgear', 'linksys', 'tp-link', 'd-link', 'asus', 'belkin']):
                if category in ['router', 'access_point']:
                    is_router = True
            
            # Port bazlı router tespiti
            for port_info in open_ports:
                port = port_info['port']
                if port == 80 or port == 443:  # Web interface
                    is_router = True
                elif port == 23:  # Telnet
                    is_router = True
                elif port == 22:  # SSH
                    is_router = True
            
            if is_router:
                routers.append({
                    'ip': ip,
                    'mac': device['mac'],
                    'vendor': device['vendor'],
                    'category': 'router',
                    'is_gateway': self.is_gateway(ip),
                    'ports': open_ports
                })
        
        return switches, routers, access_points
    
    def is_gateway(self, ip):
        """IP'nin gateway olup olmadığını kontrol et"""
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'default' in line and ip in line:
                        return True
        except:
            pass
        return False
    
    def calculate_network_metrics(self):
        """Ağ metriklerini hesapla"""
        print(f"📊 Ağ metrikleri hesaplanıyor...")
        
        metrics = {
            'total_devices': self.topology_graph.number_of_nodes(),
            'total_connections': self.topology_graph.number_of_edges(),
            'network_density': nx.density(self.topology_graph),
            'connected_components': nx.number_connected_components(self.topology_graph),
            'average_clustering': nx.average_clustering(self.topology_graph)
        }
        
        # Merkezilik ölçüleri
        try:
            metrics['centrality_measures'] = {
                'degree': nx.degree_centrality(self.topology_graph),
                'betweenness': nx.betweenness_centrality(self.topology_graph),
                'closeness': nx.closeness_centrality(self.topology_graph)
            }
        except Exception as e:
            print(f"⚠️ Merkezilik hesaplama hatası: {e}")
            metrics['centrality_measures'] = {}
        
        return metrics
    
    def assess_network_health(self):
        """Ağ sağlığını değerlendir"""
        print(f"🏥 Ağ sağlığı değerlendiriliyor...")
        
        health_score = 100
        issues = []
        
        # Bağlantı yoğunluğu kontrolü
        density = nx.density(self.topology_graph)
        if density < 0.1:
            health_score -= 20
            issues.append("Düşük ağ yoğunluğu")
        elif density > 0.8:
            health_score -= 15
            issues.append("Yüksek ağ yoğunluğu")
        
        # Bağlantılı bileşen sayısı
        components = nx.number_connected_components(self.topology_graph)
        if components > 1:
            health_score -= 25
            issues.append(f"{components} ayrı ağ bileşeni")
        
        # Merkezi cihazlar
        try:
            degree_centrality = nx.degree_centrality(self.topology_graph)
            max_degree = max(degree_centrality.values()) if degree_centrality else 0
            
            if max_degree > 0.8:
                health_score -= 10
                issues.append("Tek nokta arıza riski")
        except:
            pass
        
        # Sağlık seviyesi
        if health_score >= 80:
            health_level = "Excellent"
        elif health_score >= 60:
            health_level = "Good"
        elif health_score >= 40:
            health_level = "Fair"
        else:
            health_level = "Poor"
        
        return {
            'score': health_score,
            'level': health_level,
            'issues': issues,
            'recommendations': self.generate_recommendations(issues)
        }
    
    def generate_recommendations(self, issues):
        """Öneriler oluştur"""
        recommendations = []
        
        for issue in issues:
            if "Düşük ağ yoğunluğu" in issue:
                recommendations.append("Ağ bağlantılarını artırın")
            elif "Yüksek ağ yoğunluğu" in issue:
                recommendations.append("Ağ segmentasyonu yapın")
            elif "ayrı ağ bileşeni" in issue:
                recommendations.append("Ağ bağlantılarını kontrol edin")
            elif "Tek nokta arıza" in issue:
                recommendations.append("Yedek bağlantılar ekleyin")
        
        return recommendations
    
    def visualize_topology(self, output_file="real_topology.png"):
        """Topolojiyi görselleştir"""
        print(f"🎨 Topoloji görselleştiriliyor: {output_file}")
        
        try:
            plt.figure(figsize=(12, 8))
            
            # Node renkleri
            node_colors = []
            for node in self.topology_graph.nodes():
                if node in self.devices:
                    category = self.devices[node]['category']
                    if category == 'router':
                        node_colors.append('red')
                    elif category == 'switch':
                        node_colors.append('blue')
                    elif category == 'computer':
                        node_colors.append('green')
                    elif category == 'mobile':
                        node_colors.append('yellow')
                    elif category == 'iot':
                        node_colors.append('orange')
                    else:
                        node_colors.append('gray')
                else:
                    node_colors.append('gray')
            
            # Grafik çizimi
            pos = nx.spring_layout(self.topology_graph, k=1, iterations=50)
            nx.draw(self.topology_graph, pos, 
                   node_color=node_colors,
                   node_size=1000,
                   with_labels=True,
                   font_size=8,
                   font_weight='bold')
            
            # Legend
            legend_elements = [
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Router'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Switch'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=10, label='Computer'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='yellow', markersize=10, label='Mobile'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', markersize=10, label='IoT'),
                plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='gray', markersize=10, label='Unknown')
            ]
            plt.legend(handles=legend_elements, loc='upper right')
            
            plt.title("Real Network Topology Map")
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"✅ Topoloji haritası kaydedildi: {output_file}")
            
        except Exception as e:
            print(f"⚠️ Topoloji görselleştirme hatası: {e}")
    
    def analyze_topology(self):
        """Topoloji analizi yap"""
        print(f"🌐 Topoloji analizi başlatılıyor...")
        
        # Cihazları tara
        devices = self.scan_network_devices()
        
        # Bağlantıları keşfet
        self.discover_network_connections()
        
        # Ağ cihazlarını tanımla
        switches, routers, access_points = self.identify_network_devices()
        
        # Metrikleri hesapla
        metrics = self.calculate_network_metrics()
        
        # Ağ sağlığını değerlendir
        network_health = self.assess_network_health()
        
        # Topoloji analizi
        topology_analysis = {
            'timestamp': time.time(),
            'network_range': self.network_range,
            'total_devices': metrics['total_devices'],
            'total_connections': metrics['total_connections'],
            'network_density': metrics['network_density'],
            'connected_components': metrics['connected_components'],
            'average_clustering': metrics['average_clustering'],
            'switches': switches,
            'routers': routers,
            'access_points': access_points,
            'centrality_measures': metrics['centrality_measures'],
            'network_health': network_health,
            'devices': self.devices
        }
        
        return topology_analysis
    
    def generate_report(self, analysis):
        """Rapor oluştur"""
        print(f"📊 Rapor oluşturuluyor...")
        
        # Ana raporu kaydet
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False, default=str)
        
        # Görselleştirme
        self.visualize_topology(f"{self.output_file.replace('.json', '_topology.png')}")
        
        print(f"✅ Raporlar kaydedildi:")
        print(f"   📄 Ana rapor: {self.output_file}")
        print(f"   🎨 Topoloji haritası: {self.output_file.replace('.json', '_topology.png')}")
        
        # Özet yazdır
        print(f"\n📊 Topoloji Özeti:")
        print(f"   🌐 Ağ Aralığı: {self.network_range}")
        print(f"   📱 Toplam Cihaz: {analysis['total_devices']}")
        print(f"   🔗 Toplam Bağlantı: {analysis['total_connections']}")
        print(f"   📊 Ağ Yoğunluğu: {analysis['network_density']:.2f}")
        print(f"   🏥 Ağ Sağlığı: {analysis['network_health']['level']} ({analysis['network_health']['score']}/100)")
        
        if analysis['switches']:
            print(f"\n🔀 Switch'ler ({len(analysis['switches'])}):")
            for switch in analysis['switches']:
                print(f"   • {switch['ip']} - {switch['vendor']}")
        
        if analysis['routers']:
            print(f"\n🌐 Router'lar ({len(analysis['routers'])}):")
            for router in analysis['routers']:
                print(f"   • {router['ip']} - {router['vendor']}")
                if router.get('is_gateway'):
                    print(f"     (Gateway)")
        
        return analysis

def main():
    """Ana fonksiyon"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Gerçek Ağ Topolojisi Çıkarıcı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 real_topology_mapper.py --network 192.168.1.0/24
  sudo python3 real_topology_mapper.py --network 10.0.0.0/24 --output topology.json
  sudo python3 real_topology_mapper.py --network 172.16.0.0/16 --verbose

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
        """
    )
    
    parser.add_argument('--network', '-n', required=True,
                       help='Ağ aralığı (örn: 192.168.1.0/24)')
    parser.add_argument('--output', '-o', default='real_topology.json',
                       help='Çıktı dosyası (varsayılan: real_topology.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    # Uyarı mesajı
    print("⚠️" * 20)
    print("GERÇEK AĞ TOPOLOJİSİ ÇIKARICI")
    print("⚠️" * 20)
    print("Bu araç yalnızca eğitim ve akademik amaçlı geliştirilmiştir.")
    print("Yalnızca kendi sahip olduğunuz ağlarda kullanın.")
    print("⚠️" * 20)
    
    # Yetki kontrolü
    if os.geteuid() != 0:
        print("\n❌ Bu araç root yetkileri gerektirir!")
        print("Linux/macOS: sudo python3 real_topology_mapper.py")
        print("Windows: Administrator olarak çalıştırın")
        sys.exit(1)
    
    # Mapper oluştur
    mapper = RealTopologyMapper(network_range=args.network, output_file=args.output)
    
    try:
        # Topoloji analizi
        analysis = mapper.analyze_topology()
        
        if analysis:
            # Rapor oluştur
            mapper.generate_report(analysis)
            print(f"\n✅ Topoloji analizi tamamlandı!")
        else:
            print(f"\n❌ Topoloji analizi başarısız!")
    
    except KeyboardInterrupt:
        print("\n⏹️  Analiz kullanıcı tarafından durduruldu")
        
    except Exception as e:
        print(f"❌ Genel hata: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()



