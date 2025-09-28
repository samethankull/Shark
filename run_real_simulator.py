#!/usr/bin/env python3
"""
Gerçek Ağ Simülatörü Çalıştırıcı
================================

Bu script, real_network_simulator.py modülünü kolayca çalıştırır.
GERÇEK PAKETLER GÖNDERİR - dikkatli kullanın!
"""

import sys
import os
import argparse
import time
import json

def main():
    """Ana fonksiyon"""
    parser = argparse.ArgumentParser(
        description="Gerçek Ağ Simülatörü Çalıştırıcı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 run_real_simulator.py --quick
  sudo python3 run_real_simulator.py --analyze-real 192.168.1.0/24
  sudo python3 run_real_simulator.py --custom --devices 50 --duration 1800
  sudo python3 run_real_simulator.py --attack-simulation

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
   GERÇEK PAKETLER GÖNDERİR - dikkatli kullanın!
        """
    )
    
    parser.add_argument('--quick', '-q', action='store_true',
                       help='Hızlı simülasyon (10 cihaz, 5 dakika)')
    parser.add_argument('--analyze-real', '-a', 
                       help='Gerçek ağı analiz et ve simüle et (örn: 192.168.1.0/24)')
    parser.add_argument('--custom', '-c', action='store_true',
                       help='Özel simülasyon parametreleri')
    parser.add_argument('--devices', '-n', type=int, default=25,
                       help='Simüle edilecek cihaz sayısı (varsayılan: 25)')
    parser.add_argument('--duration', '-d', type=int, default=3600,
                       help='Simülasyon süresi saniye (varsayılan: 3600)')
    parser.add_argument('--network', '-net', default='192.168.100.0/24',
                       help='Simülasyon ağ aralığı (varsayılan: 192.168.100.0/24)')
    parser.add_argument('--attack-simulation', '-att', action='store_true',
                       help='Saldırı simülasyonu dahil et (eğitim amaçlı)')
    parser.add_argument('--output', '-o', default='real_simulation_report.json',
                       help='Çıktı dosyası (varsayılan: real_simulation_report.json)')
    parser.add_argument('--config', '-cfg', default='simulation_config.json',
                       help='Konfigürasyon dosyası (varsayılan: simulation_config.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    print("🎭 Gerçek Ağ Simülatörü Çalıştırıcı")
    print("=" * 60)
    print("⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!")
    print("   GERÇEK PAKETLER GÖNDERİR - dikkatli kullanın!")
    print("   Yalnızca test ortamlarında kullanın.")
    print("=" * 60)
    
    # Simülasyon parametrelerini belirle
    if args.quick:
        devices = 10
        duration = 300  # 5 dakika
        network = '192.168.100.0/24'
        attacks = False
        print("🚀 Hızlı gerçek simülasyon modu seçildi")
    elif args.analyze_real:
        devices = 20
        duration = 600  # 10 dakika
        network = args.analyze_real
        attacks = False
        print(f"🔍 Gerçek ağ analizi modu: {args.analyze_real}")
    elif args.custom:
        devices = args.devices
        duration = args.duration
        network = args.network
        attacks = args.attack_simulation
        print("⚙️ Özel gerçek simülasyon modu seçildi")
    else:
        # Varsayılan parametreler
        devices = args.devices
        duration = args.duration
        network = args.network
        attacks = args.attack_simulation
    
    # Konfigürasyon dosyasını oluştur
    config = {
        "simulation": {
            "duration": duration,
            "device_count": devices,
            "traffic_intensity": "medium",
            "network_range": network,
            "simulate_web_traffic": True,
            "simulate_iot_devices": True,
            "simulate_attacks": attacks,
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
    
    # Geçici konfigürasyon dosyası oluştur
    temp_config_file = f"temp_real_config_{int(time.time())}.json"
    with open(temp_config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    try:
        # Simülasyon parametrelerini yazdır
        print(f"\n📊 Gerçek Simülasyon Parametreleri:")
        print(f"   Cihaz Sayısı: {devices}")
        print(f"   Süre: {duration} saniye ({duration//60} dakika)")
        print(f"   Ağ Aralığı: {network}")
        print(f"   Saldırı Simülasyonu: {'Evet' if attacks else 'Hayır'}")
        print(f"   Çıktı Dosyası: {args.output}")
        print(f"   GERÇEK PAKETLER GÖNDERİLECEK!")
        
        # Simülasyonu başlat
        print(f"\n🚀 Gerçek simülasyon başlatılıyor...")
        
        # real_network_simulator.py'yi import et ve çalıştır
        from real_network_simulator import RealNetworkSimulator
        
        simulator = RealNetworkSimulator(temp_config_file)
        
        # Gerçek ağ analizi (isteğe bağlı)
        real_network_range = args.analyze_real if args.analyze_real else None
        
        # Simülasyonu başlat
        simulator.start_simulation(real_network_range)
        
        # Simülasyon süresini bekle
        print(f"⏱️ Simülasyon {duration} saniye çalışacak...")
        print("💡 Simülasyonu durdurmak için Ctrl+C kullanın")
        print("⚠️  GERÇEK PAKETLER GÖNDERİLİYOR!")
        
        time.sleep(duration)
        
        # Simülasyonu durdur
        simulator.stop_simulation()
        
        # Rapor oluştur
        report = simulator.generate_simulation_report(args.output)
        
        # Özet yazdır
        simulator.print_simulation_summary()
        
        print(f"\n✅ Gerçek simülasyon tamamlandı!")
        print(f"📊 Rapor: {args.output}")
        print(f"📦 Toplam gönderilen paket: {simulator.packet_count}")
        
        # Geçici dosyayı temizle
        if os.path.exists(temp_config_file):
            os.remove(temp_config_file)
        
    except KeyboardInterrupt:
        print("\n⏹️ Simülasyon kullanıcı tarafından durduruldu")
        if 'simulator' in locals():
            simulator.stop_simulation()
        
        # Geçici dosyayı temizle
        if os.path.exists(temp_config_file):
            os.remove(temp_config_file)
            
    except ImportError as e:
        print(f"❌ Modül import hatası: {e}")
        print("💡 real_network_simulator.py dosyasının mevcut olduğundan emin olun")
        
    except Exception as e:
        print(f"❌ Simülasyon hatası: {e}")
        if 'simulator' in locals():
            simulator.stop_simulation()
        
        # Geçici dosyayı temizle
        if os.path.exists(temp_config_file):
            os.remove(temp_config_file)


if __name__ == "__main__":
    main()



