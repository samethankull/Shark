#!/usr/bin/env python3
"""
Gerçek Analiz Çalıştırıcı
=========================

Bu script, gerçek verilerle çalışan tüm modülleri sırayla çalıştırır.
"""

import sys
import os
import argparse
import time
import json
import subprocess
from datetime import datetime

def run_command(cmd, description):
    """Komut çalıştır ve sonucu döndür"""
    print(f"\n🔍 {description}")
    print(f"Komut: {cmd}")
    print("-" * 50)
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            print("✅ Başarılı!")
            return True, result.stdout
        else:
            print("❌ Hata!")
            if result.stderr:
                print(f"Hata: {result.stderr}")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        print("⏰ Zaman aşımı!")
        return False, "Timeout"
    except Exception as e:
        print(f"❌ Komut hatası: {e}")
        return False, str(e)

def main():
    """Ana fonksiyon"""
    parser = argparse.ArgumentParser(
        description="Gerçek Analiz Çalıştırıcı - Tüm Modüller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 run_real_analysis.py --network 192.168.1.0/24
  sudo python3 run_real_analysis.py --network 192.168.1.0/24 --duration 300
  sudo python3 run_real_analysis.py --network 10.0.0.0/24 --output real_analysis.json

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
        """
    )
    
    parser.add_argument('--network', '-n', required=True,
                       help='Ağ aralığı (örn: 192.168.1.0/24)')
    parser.add_argument('--duration', '-d', type=int, default=300,
                       help='Web aktivite izleme süresi (saniye, varsayılan: 300)')
    parser.add_argument('--output', '-o', default='real_analysis_report.json',
                       help='Birleşik rapor dosyası (varsayılan: real_analysis_report.json)')
    parser.add_argument('--skip-modules', '-s', nargs='+', 
                       choices=['scanner', 'topology', 'web'],
                       help='Atlanacak modüller')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    print("🚀 Gerçek Analiz Çalıştırıcı - Tüm Modüller")
    print("=" * 60)
    print("⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!")
    print("   Yalnızca kendi sahip olduğunuz ağlarda kullanın.")
    print("=" * 60)
    
    # Atlanacak modüller
    skip_modules = args.skip_modules or []
    
    # Sonuçları sakla
    results = {
        'timestamp': time.time(),
        'network': args.network,
        'duration': args.duration,
        'modules_run': [],
        'modules_skipped': skip_modules,
        'results': {}
    }
    
    try:
        # 1. Gerçek Ağ Tarayıcı
        if 'scanner' not in skip_modules:
            print(f"\n{'='*60}")
            print("📱 1. GERÇEK AĞ TARAYICI")
            print(f"{'='*60}")
            
            cmd = f"python3 real_network_scanner.py --network {args.network} --output real_network_scan.json"
            
            success, output = run_command(cmd, "Gerçek Ağ Tarama")
            results['modules_run'].append('real_network_scanner')
            results['results']['real_network_scanner'] = {
                'success': success,
                'output': output[:500] if output else None
            }
        
        # 2. Gerçek Topoloji Analizi
        if 'topology' not in skip_modules:
            print(f"\n{'='*60}")
            print("🌐 2. GERÇEK TOPOLOJİ ANALİZİ")
            print(f"{'='*60}")
            
            cmd = f"python3 real_topology_mapper.py --network {args.network} --output real_topology.json"
            
            success, output = run_command(cmd, "Gerçek Topoloji Analizi")
            results['modules_run'].append('real_topology_mapper')
            results['results']['real_topology_mapper'] = {
                'success': success,
                'output': output[:500] if output else None
            }
        
        # 3. Gerçek Zamanlı Web Aktivite İzleme
        if 'web' not in skip_modules:
            print(f"\n{'='*60}")
            print("🌍 3. GERÇEK ZAMANLI WEB AKTİVİTE İZLEME")
            print(f"{'='*60}")
            
            cmd = f"python3 real_time_web_monitor.py --auto-interface --duration {args.duration} --output real_web_activity.json"
            
            success, output = run_command(cmd, "Gerçek Zamanlı Web Aktivite İzleme")
            results['modules_run'].append('real_time_web_monitor')
            results['results']['real_time_web_monitor'] = {
                'success': success,
                'output': output[:500] if output else None
            }
        
        # 4. Sonuçları Birleştir
        print(f"\n{'='*60}")
        print("📊 4. SONUÇLARI BİRLEŞTİR")
        print(f"{'='*60}")
        
        # Başarılı modül sayısı
        successful_modules = sum(1 for result in results['results'].values() if result['success'])
        total_modules = len(results['modules_run'])
        
        print(f"✅ Başarılı Modül: {successful_modules}/{total_modules}")
        print(f"⏭️  Atlanan Modül: {len(skip_modules)}")
        
        # Her modül için özet
        for module, result in results['results'].items():
            status = "✅" if result['success'] else "❌"
            print(f"   {status} {module}")
        
        # Birleşik raporu kaydet
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n✅ Birleşik rapor kaydedildi: {args.output}")
        
        # Oluşturulan dosyaları listele
        print(f"\n📁 Oluşturulan Dosyalar:")
        import glob
        
        # JSON dosyalarını bul
        json_files = glob.glob("real_*.json")
        png_files = glob.glob("real_*.png")
        
        for file in sorted(json_files):
            if file != args.output:  # Ana raporu hariç tut
                print(f"   📄 {file}")
        
        for file in sorted(png_files):
            print(f"   🎨 {file}")
        
        # Genel özet
        print(f"\n🎯 GENEL ÖZET:")
        print(f"   Ağ: {args.network}")
        print(f"   İzleme Süresi: {args.duration} saniye")
        print(f"   Çalıştırılan Modül: {len(results['modules_run'])}")
        print(f"   Başarılı Modül: {successful_modules}")
        print(f"   Toplam Süre: {time.time() - results['timestamp']:.1f} saniye")
        
        if successful_modules == total_modules:
            print(f"\n🎉 Tüm modüller başarıyla çalıştırıldı!")
            print("Artık gerçek verilerle analiz yapabilirsiniz.")
        elif successful_modules > 0:
            print(f"\n⚠️  Bazı modüller başarısız oldu, kontrol edin.")
        else:
            print(f"\n❌ Hiçbir modül başarıyla çalıştırılamadı!")
        
        # Kullanım önerileri
        print(f"\n💡 KULLANIM ÖNERİLERİ:")
        print(f"   📄 JSON raporlarını inceleyin")
        print(f"   🎨 PNG topoloji haritalarını görüntüleyin")
        print(f"   📊 Wireshark ile PCAP dosyalarını analiz edin")
        print(f"   🔍 Gerçek ağ trafiğini gözlemleyin")
    
    except Exception as e:
        print(f"❌ Genel hata: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()



