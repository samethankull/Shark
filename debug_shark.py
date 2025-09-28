#!/usr/bin/env python3
"""
Shark Debug Scripti
===================

Bu script, shark.py'nin çalışıp çalışmadığını test eder.
"""

import sys
import os

def test_basic_imports():
    """Temel import testleri"""
    print("🔍 Temel import testleri...")
    
    try:
        import argparse
        print("✅ argparse")
        
        import logging
        print("✅ logging")
        
        import json
        print("✅ json")
        
        import time
        print("✅ time")
        
        import threading
        print("✅ threading")
        
        from collections import defaultdict, Counter
        print("✅ collections")
        
        import subprocess
        print("✅ subprocess")
        
        import re
        print("✅ re")
        
        return True
        
    except Exception as e:
        print(f"❌ Temel import hatası: {e}")
        return False

def test_scapy_imports():
    """Scapy import testleri"""
    print("\n🔍 Scapy import testleri...")
    
    try:
        from scapy.all import *
        print("✅ scapy.all")
        
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        print("✅ scapy.layers.inet")
        
        from scapy.layers.l2 import Ether, ARP
        print("✅ scapy.layers.l2")
        
        from scapy.layers.dns import DNS, DNSQR
        print("✅ scapy.layers.dns")
        
        from scapy.layers.http import HTTPRequest, HTTPResponse
        print("✅ scapy.layers.http")
        
        return True
        
    except Exception as e:
        print(f"❌ Scapy import hatası: {e}")
        return False

def test_other_imports():
    """Diğer import testleri"""
    print("\n🔍 Diğer import testleri...")
    
    try:
        import nmap
        print("✅ nmap")
        
        import requests
        print("✅ requests")
        
        try:
            import networkx as nx
            print("✅ networkx")
        except:
            print("⚠️ networkx (isteğe bağlı)")
        
        try:
            import matplotlib.pyplot as plt
            print("✅ matplotlib")
        except:
            print("⚠️ matplotlib (isteğe bağlı)")
        
        return True
        
    except Exception as e:
        print(f"❌ Diğer import hatası: {e}")
        return False

def test_advanced_modules():
    """Gelişmiş modül testleri"""
    print("\n🔍 Gelişmiş modül testleri...")
    
    modules = [
        ("advanced_device_detection", "AdvancedDeviceDetector"),
        ("network_topology", "NetworkTopologyMapper"),
        ("penetration_testing", "PenetrationTester"),
        ("web_activity_monitor", "WebActivityMonitor")
    ]
    
    results = {}
    
    for module_name, class_name in modules:
        try:
            module = __import__(module_name)
            class_obj = getattr(module, class_name)
            print(f"✅ {module_name}.{class_name}")
            results[module_name] = True
        except Exception as e:
            print(f"❌ {module_name}.{class_name}: {e}")
            results[module_name] = False
    
    return results

def main():
    """Ana test fonksiyonu"""
    print("🧪 Shark Debug Scripti")
    print("=" * 40)
    
    # Temel import testleri
    basic_ok = test_basic_imports()
    
    # Scapy import testleri
    scapy_ok = test_scapy_imports()
    
    # Diğer import testleri
    other_ok = test_other_imports()
    
    # Gelişmiş modül testleri
    advanced_results = test_advanced_modules()
    
    print("\n📊 Test Sonuçları:")
    print(f"   Temel Modüller: {'✅' if basic_ok else '❌'}")
    print(f"   Scapy: {'✅' if scapy_ok else '❌'}")
    print(f"   Diğer Modüller: {'✅' if other_ok else '❌'}")
    
    print("\n🔧 Gelişmiş Modüller:")
    for module, result in advanced_results.items():
        print(f"   {module}: {'✅' if result else '❌'}")
    
    if basic_ok and scapy_ok and other_ok:
        print("\n🎉 Temel modüller çalışıyor!")
        print("Shark.py çalıştırılabilir.")
        
        if all(advanced_results.values()):
            print("🎉 Tüm gelişmiş modüller çalışıyor!")
            print("--web-activity, --topology, --penetration komutları kullanılabilir.")
        else:
            print("⚠️  Bazı gelişmiş modüller çalışmıyor.")
            print("Sadece temel özellikler kullanılabilir.")
    else:
        print("\n❌ Temel modüller çalışmıyor!")
        print("Lütfen gerekli kütüphaneleri kurun:")
        print("pip install scapy python-nmap requests")

if __name__ == "__main__":
    main()




