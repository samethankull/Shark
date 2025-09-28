#!/usr/bin/env python3
"""
Gerçek Penetrasyon Testi - Real Penetration Tester
=================================================

Bu modül, gerçek penetrasyon testleri yapar:
- Port tarama
- Güvenlik açığı tespiti
- Zayıf kimlik bilgileri testi
- SSL/TLS güvenlik analizi
- Servis güvenlik testleri

⚠️ UYARI: Bu araç yalnızca eğitim amaçlıdır!
"""

import nmap
import socket
import ssl
import subprocess
import json
import time
import threading
from datetime import datetime
from collections import defaultdict, Counter
import requests
import paramiko
import telnetlib
import ftplib
import smtplib
import poplib
import imaplib
import pymssql
import psycopg2
from urllib.parse import urlparse

class RealPenetrationTester:
    """Gerçek penetrasyon testi sınıfı"""
    
    def __init__(self, output_file="real_penetration_report.json"):
        self.output_file = output_file
        self.nm = nmap.PortScanner()
        self.vulnerabilities = []
        self.test_results = {}
        self.credentials_tested = 0
        self.ports_scanned = 0
        
        print("🔒 Gerçek Penetrasyon Testi başlatıldı")
        print(f"💾 Çıktı dosyası: {self.output_file}")
    
    def scan_target(self, target, port_range="1-1000"):
        """Hedefi tara"""
        print(f"🎯 Hedef taranıyor: {target}")
        
        try:
            # Nmap ile port tarama
            scan_result = self.nm.scan(target, port_range, arguments='-sS -sV -O --script vuln')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                self.test_results[target] = {
                    'hostname': host_info.hostname(),
                    'state': host_info.state(),
                    'os_info': host_info.get('osmatch', []),
                    'open_ports': {},
                    'vulnerabilities': [],
                    'timestamp': datetime.now().isoformat()
                }
                
                # Açık portları analiz et
                for port in host_info['tcp']:
                    port_info = host_info['tcp'][port]
                    if port_info['state'] == 'open':
                        self.test_results[target]['open_ports'][port] = port_info
                        self.ports_scanned += 1
                        
                        # Port güvenlik testi
                        self.test_port_security(target, port, port_info)
                
                print(f"✅ {target} taranıyor: {len(self.test_results[target]['open_ports'])} açık port")
                return self.test_results[target]
            else:
                print(f"❌ {target} erişilemiyor")
                return None
                
        except Exception as e:
            print(f"❌ Tarama hatası: {e}")
            return None
    
    def test_port_security(self, target, port, port_info):
        """Port güvenlik testi"""
        service = port_info.get('name', '').lower()
        version = port_info.get('version', '')
        
        print(f"🔍 Port {port} ({service}) güvenlik testi...")
        
        # SSH güvenlik testi
        if service == 'ssh':
            self.test_ssh_security(target, port)
        
        # HTTP/HTTPS güvenlik testi
        elif service in ['http', 'https']:
            self.test_web_security(target, port, service)
        
        # FTP güvenlik testi
        elif service == 'ftp':
            self.test_ftp_security(target, port)
        
        # Telnet güvenlik testi
        elif service == 'telnet':
            self.test_telnet_security(target, port)
        
        # SMTP güvenlik testi
        elif service == 'smtp':
            self.test_smtp_security(target, port)
        
        # POP3 güvenlik testi
        elif service == 'pop3':
            self.test_pop3_security(target, port)
        
        # IMAP güvenlik testi
        elif service == 'imap':
            self.test_imap_security(target, port)
        
        # MSSQL güvenlik testi
        elif service == 'mssql':
            self.test_mssql_security(target, port)
        
        # PostgreSQL güvenlik testi
        elif service == 'postgresql':
            self.test_postgresql_security(target, port)
    
    def test_ssh_security(self, target, port):
        """SSH güvenlik testi"""
        print(f"🔐 SSH güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # SSH bağlantısı test et
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Zayıf kimlik bilgileri test et
            weak_credentials = [
                ('admin', 'admin'),
                ('root', 'root'),
                ('admin', 'password'),
                ('root', 'password'),
                ('admin', '123456'),
                ('root', '123456'),
                ('admin', 'admin123'),
                ('root', 'root123'),
                ('user', 'user'),
                ('guest', 'guest')
            ]
            
            for username, password in weak_credentials:
                try:
                    ssh.connect(target, port=port, username=username, password=password, timeout=5)
                    vulnerabilities.append({
                        'type': 'weak_credentials',
                        'service': 'ssh',
                        'username': username,
                        'password': password,
                        'severity': 'high',
                        'description': f'Zayıf SSH kimlik bilgileri: {username}:{password}'
                    })
                    ssh.close()
                    self.credentials_tested += 1
                    break
                except:
                    self.credentials_tested += 1
                    continue
            
            # SSH versiyon kontrolü
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                
                # SSH banner al
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if 'SSH-1.' in banner:
                    vulnerabilities.append({
                        'type': 'outdated_protocol',
                        'service': 'ssh',
                        'severity': 'high',
                        'description': 'Eski SSH protokolü (SSH-1) kullanılıyor'
                    })
                
                if 'OpenSSH' in banner and '7.0' in banner:
                    vulnerabilities.append({
                        'type': 'outdated_version',
                        'service': 'ssh',
                        'severity': 'medium',
                        'description': 'Eski OpenSSH versiyonu kullanılıyor'
                    })
                
            except:
                pass
                
        except Exception as e:
            print(f"⚠️ SSH test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_web_security(self, target, port, service):
        """Web güvenlik testi"""
        print(f"🌐 Web güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        protocol = 'https' if service == 'https' else 'http'
        url = f"{protocol}://{target}:{port}"
        
        try:
            # HTTP başlık güvenlik testi
            response = requests.get(url, timeout=10, verify=False)
            
            # Güvenlik başlıkları kontrol et
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'missing_security_headers',
                    'service': 'web',
                    'severity': 'medium',
                    'description': f'Eksik güvenlik başlıkları: {", ".join(missing_headers)}'
                })
            
            # Server bilgisi kontrol et
            server = response.headers.get('Server', '')
            if 'Apache' in server and '2.2' in server:
                vulnerabilities.append({
                    'type': 'outdated_server',
                    'service': 'web',
                    'severity': 'high',
                    'description': 'Eski Apache versiyonu kullanılıyor'
                })
            
            # HTTPS testi
            if service == 'https':
                self.test_ssl_security(target, port)
                
        except Exception as e:
            print(f"⚠️ Web test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_ssl_security(self, target, port):
        """SSL/TLS güvenlik testi"""
        print(f"🔒 SSL/TLS güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # SSL bağlantısı oluştur
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # SSL bilgilerini al
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # SSL versiyon kontrolü
                    if version in ['SSLv2', 'SSLv3', 'TLSv1']:
                        vulnerabilities.append({
                            'type': 'weak_ssl_version',
                            'service': 'ssl',
                            'severity': 'high',
                            'description': f'Zayıf SSL/TLS versiyonu: {version}'
                        })
                    
                    # Cipher kontrolü
                    if cipher and 'RC4' in cipher[0]:
                        vulnerabilities.append({
                            'type': 'weak_cipher',
                            'service': 'ssl',
                            'severity': 'high',
                            'description': f'Zayıf şifreleme: {cipher[0]}'
                        })
                    
                    # Sertifika kontrolü
                    if cert:
                        # Sertifika süresi kontrol et
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.datetime.now():
                            vulnerabilities.append({
                                'type': 'expired_certificate',
                                'service': 'ssl',
                                'severity': 'medium',
                                'description': 'Süresi dolmuş SSL sertifikası'
                            })
                        
                        # Sertifika imzalama algoritması kontrol et
                        if 'sha1' in cert.get('signatureAlgorithm', '').lower():
                            vulnerabilities.append({
                                'type': 'weak_signature',
                                'service': 'ssl',
                                'severity': 'medium',
                                'description': 'Zayıf sertifika imzalama algoritması (SHA1)'
                            })
                        
        except Exception as e:
            print(f"⚠️ SSL test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_ftp_security(self, target, port):
        """FTP güvenlik testi"""
        print(f"📁 FTP güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # FTP bağlantısı test et
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=10)
            
            # Anonymous login test et
            try:
                ftp.login('anonymous', 'anonymous')
                vulnerabilities.append({
                    'type': 'anonymous_ftp',
                    'service': 'ftp',
                    'severity': 'medium',
                    'description': 'Anonymous FTP erişimi mümkün'
                })
                ftp.quit()
            except:
                pass
            
            # Zayıf kimlik bilgileri test et
            weak_credentials = [
                ('admin', 'admin'),
                ('ftp', 'ftp'),
                ('user', 'user'),
                ('guest', 'guest'),
                ('anonymous', ''),
                ('root', 'root')
            ]
            
            for username, password in weak_credentials:
                try:
                    ftp.connect(target, port, timeout=5)
                    ftp.login(username, password)
                    vulnerabilities.append({
                        'type': 'weak_credentials',
                        'service': 'ftp',
                        'username': username,
                        'password': password,
                        'severity': 'high',
                        'description': f'Zayıf FTP kimlik bilgileri: {username}:{password}'
                    })
                    ftp.quit()
                    self.credentials_tested += 1
                    break
                except:
                    self.credentials_tested += 1
                    continue
                    
        except Exception as e:
            print(f"⚠️ FTP test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_telnet_security(self, target, port):
        """Telnet güvenlik testi"""
        print(f"📞 Telnet güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # Telnet bağlantısı test et
            tn = telnetlib.Telnet(target, port, timeout=10)
            
            # Banner al
            banner = tn.read_until(b"login:", timeout=5).decode('utf-8', errors='ignore')
            
            # Zayıf kimlik bilgileri test et
            weak_credentials = [
                ('admin', 'admin'),
                ('root', 'root'),
                ('user', 'user'),
                ('guest', 'guest'),
                ('admin', 'password'),
                ('root', 'password')
            ]
            
            for username, password in weak_credentials:
                try:
                    tn.write(username.encode('ascii') + b"\n")
                    tn.read_until(b"Password:", timeout=5)
                    tn.write(password.encode('ascii') + b"\n")
                    
                    response = tn.read_until(b"$", timeout=5).decode('utf-8', errors='ignore')
                    if '$' in response or '#' in response:
                        vulnerabilities.append({
                            'type': 'weak_credentials',
                            'service': 'telnet',
                            'username': username,
                            'password': password,
                            'severity': 'critical',
                            'description': f'Zayıf Telnet kimlik bilgileri: {username}:{password}'
                        })
                        self.credentials_tested += 1
                        break
                except:
                    self.credentials_tested += 1
                    continue
            
            tn.close()
            
            # Telnet kullanımı güvenlik riski
            vulnerabilities.append({
                'type': 'insecure_protocol',
                'service': 'telnet',
                'severity': 'high',
                'description': 'Telnet protokolü şifrelenmemiş veri gönderir'
            })
            
        except Exception as e:
            print(f"⚠️ Telnet test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_smtp_security(self, target, port):
        """SMTP güvenlik testi"""
        print(f"📧 SMTP güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # SMTP bağlantısı test et
            server = smtplib.SMTP(target, port, timeout=10)
            
            # SMTP bilgilerini al
            server.ehlo()
            capabilities = server.esmtp_features
            
            # Open relay test et
            try:
                server.mail('test@example.com')
                server.rcpt('test@external.com')
                vulnerabilities.append({
                    'type': 'open_relay',
                    'service': 'smtp',
                    'severity': 'high',
                    'description': 'SMTP open relay mümkün'
                })
            except:
                pass
            
            server.quit()
            
        except Exception as e:
            print(f"⚠️ SMTP test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_pop3_security(self, target, port):
        """POP3 güvenlik testi"""
        print(f"📬 POP3 güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # POP3 bağlantısı test et
            server = poplib.POP3(target, port, timeout=10)
            
            # Zayıf kimlik bilgileri test et
            weak_credentials = [
                ('admin', 'admin'),
                ('user', 'user'),
                ('test', 'test'),
                ('admin', 'password'),
                ('user', 'password')
            ]
            
            for username, password in weak_credentials:
                try:
                    server.user(username)
                    server.pass_(password)
                    vulnerabilities.append({
                        'type': 'weak_credentials',
                        'service': 'pop3',
                        'username': username,
                        'password': password,
                        'severity': 'high',
                        'description': f'Zayıf POP3 kimlik bilgileri: {username}:{password}'
                    })
                    server.quit()
                    self.credentials_tested += 1
                    break
                except:
                    self.credentials_tested += 1
                    continue
            
        except Exception as e:
            print(f"⚠️ POP3 test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_imap_security(self, target, port):
        """IMAP güvenlik testi"""
        print(f"📭 IMAP güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # IMAP bağlantısı test et
            server = imaplib.IMAP4(target, port)
            
            # Zayıf kimlik bilgileri test et
            weak_credentials = [
                ('admin', 'admin'),
                ('user', 'user'),
                ('test', 'test'),
                ('admin', 'password'),
                ('user', 'password')
            ]
            
            for username, password in weak_credentials:
                try:
                    server.login(username, password)
                    vulnerabilities.append({
                        'type': 'weak_credentials',
                        'service': 'imap',
                        'username': username,
                        'password': password,
                        'severity': 'high',
                        'description': f'Zayıf IMAP kimlik bilgileri: {username}:{password}'
                    })
                    server.logout()
                    self.credentials_tested += 1
                    break
                except:
                    self.credentials_tested += 1
                    continue
            
        except Exception as e:
            print(f"⚠️ IMAP test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_mssql_security(self, target, port):
        """MSSQL güvenlik testi"""
        print(f"🗄️ MSSQL güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # Zayıf kimlik bilgileri test et
            weak_credentials = [
                ('sa', ''),
                ('sa', 'sa'),
                ('sa', 'password'),
                ('admin', 'admin'),
                ('user', 'user')
            ]
            
            for username, password in weak_credentials:
                try:
                    conn = pymssql.connect(target, username, password, timeout=5)
                    vulnerabilities.append({
                        'type': 'weak_credentials',
                        'service': 'mssql',
                        'username': username,
                        'password': password,
                        'severity': 'critical',
                        'description': f'Zayıf MSSQL kimlik bilgileri: {username}:{password}'
                    })
                    conn.close()
                    self.credentials_tested += 1
                    break
                except:
                    self.credentials_tested += 1
                    continue
                    
        except Exception as e:
            print(f"⚠️ MSSQL test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def test_postgresql_security(self, target, port):
        """PostgreSQL güvenlik testi"""
        print(f"🐘 PostgreSQL güvenlik testi: {target}:{port}")
        
        vulnerabilities = []
        
        try:
            # Zayıf kimlik bilgileri test et
            weak_credentials = [
                ('postgres', ''),
                ('postgres', 'postgres'),
                ('postgres', 'password'),
                ('admin', 'admin'),
                ('user', 'user')
            ]
            
            for username, password in weak_credentials:
                try:
                    conn = psycopg2.connect(
                        host=target,
                        port=port,
                        user=username,
                        password=password,
                        connect_timeout=5
                    )
                    vulnerabilities.append({
                        'type': 'weak_credentials',
                        'service': 'postgresql',
                        'username': username,
                        'password': password,
                        'severity': 'critical',
                        'description': f'Zayıf PostgreSQL kimlik bilgileri: {username}:{password}'
                    })
                    conn.close()
                    self.credentials_tested += 1
                    break
                except:
                    self.credentials_tested += 1
                    continue
                    
        except Exception as e:
            print(f"⚠️ PostgreSQL test hatası: {e}")
        
        # Vulnerabilities'leri kaydet
        if vulnerabilities:
            self.vulnerabilities.extend(vulnerabilities)
            if target in self.test_results:
                self.test_results[target]['vulnerabilities'].extend(vulnerabilities)
    
    def generate_penetration_report(self):
        """Penetrasyon testi raporu oluştur"""
        print("📊 Penetrasyon testi raporu oluşturuluyor...")
        
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_targets': len(self.test_results),
                'total_vulnerabilities': len(self.vulnerabilities),
                'credentials_tested': self.credentials_tested,
                'ports_scanned': self.ports_scanned,
                'tester': 'Real Penetration Tester'
            },
            'test_results': self.test_results,
            'vulnerabilities': self.vulnerabilities,
            'statistics': self.calculate_penetration_statistics()
        }
        
        # Raporu kaydet
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Penetrasyon testi raporu kaydedildi: {self.output_file}")
        return report
    
    def calculate_penetration_statistics(self):
        """Penetrasyon testi istatistiklerini hesapla"""
        stats = {
            'total_targets': len(self.test_results),
            'total_vulnerabilities': len(self.vulnerabilities),
            'credentials_tested': self.credentials_tested,
            'ports_scanned': self.ports_scanned,
            'vulnerability_types': Counter(),
            'severity_levels': Counter(),
            'services_tested': Counter(),
            'open_ports': 0
        }
        
        # Vulnerability istatistikleri
        for vuln in self.vulnerabilities:
            stats['vulnerability_types'][vuln['type']] += 1
            stats['severity_levels'][vuln['severity']] += 1
            stats['services_tested'][vuln['service']] += 1
        
        # Açık port istatistikleri
        for target_data in self.test_results.values():
            stats['open_ports'] += len(target_data.get('open_ports', {}))
        
        return dict(stats)
    
    def print_penetration_summary(self):
        """Penetrasyon testi özetini yazdır"""
        print("\n" + "="*60)
        print("🔒 GERÇEK PENETRASYON TESTİ ÖZETİ")
        print("="*60)
        
        print(f"🎯 Toplam Hedef: {len(self.test_results)}")
        print(f"🔍 Taranan Port: {self.ports_scanned}")
        print(f"🔐 Test Edilen Kimlik Bilgisi: {self.credentials_tested}")
        print(f"⚠️ Bulunan Güvenlik Açığı: {len(self.vulnerabilities)}")
        
        # Güvenlik açığı türleri
        print(f"\n🔍 Güvenlik Açığı Türleri:")
        vuln_types = Counter(v['type'] for v in self.vulnerabilities)
        for vuln_type, count in vuln_types.items():
            print(f"   {vuln_type}: {count}")
        
        # Önem seviyeleri
        print(f"\n⚠️ Önem Seviyeleri:")
        severity_levels = Counter(v['severity'] for v in self.vulnerabilities)
        for severity, count in severity_levels.items():
            print(f"   {severity}: {count}")
        
        # Test edilen servisler
        print(f"\n🔧 Test Edilen Servisler:")
        services = Counter(v['service'] for v in self.vulnerabilities)
        for service, count in services.items():
            print(f"   {service}: {count}")
        
        print("="*60)


def main():
    """Ana fonksiyon"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Gerçek Penetrasyon Testi - Real Penetration Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanım:
  sudo python3 real_penetration_tester.py --target 192.168.1.1
  sudo python3 real_penetration_tester.py --target 192.168.1.0/24
  sudo python3 real_penetration_tester.py --target 192.168.1.1 --ports 1-1000

⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
        """
    )
    
    parser.add_argument('--target', '-t', required=True,
                       help='Hedef IP adresi veya ağ aralığı')
    parser.add_argument('--ports', '-p', default='1-1000',
                       help='Taranacak port aralığı (varsayılan: 1-1000)')
    parser.add_argument('--output', '-o', default='real_penetration_report.json',
                       help='Çıktı dosyası (varsayılan: real_penetration_report.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Detaylı çıktı')
    
    args = parser.parse_args()
    
    print("🔒 Gerçek Penetrasyon Testi - Real Penetration Tester")
    print("=" * 60)
    print("⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!")
    print("   Yalnızca kendi sahip olduğunuz ağlarda kullanın.")
    print("=" * 60)
    
    # Penetrasyon testi oluştur
    tester = RealPenetrationTester(args.output)
    
    try:
        # Hedefi tara
        result = tester.scan_target(args.target, args.ports)
        
        if result:
            # Rapor oluştur
            report = tester.generate_penetration_report()
            
            # Özet yazdır
            tester.print_penetration_summary()
            
            print(f"\n✅ Penetrasyon testi tamamlandı!")
            print(f"📊 Rapor: {args.output}")
        else:
            print("❌ Penetrasyon testi başarısız")
        
    except KeyboardInterrupt:
        print("\n⏹️ Test kullanıcı tarafından durduruldu")
    except Exception as e:
        print(f"❌ Penetrasyon testi hatası: {e}")


if __name__ == "__main__":
    main()



