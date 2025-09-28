#!/bin/bash

# Etik Ağ İzleme Aracı - Kurulum Scripti
# Academic Network Monitor - Installation Script

echo "🔍 Etik Ağ İzleme Aracı Kurulumu"
echo "================================="
echo ""

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Uyarı mesajı
echo -e "${RED}⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!${NC}"
echo -e "${RED}   Yalnızca kendi sahip olduğunuz ağlarda kullanın.${NC}"
echo ""

# Root kontrolü
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Root olarak çalıştırıyorsunuz. Normal kullanıcı olarak çalıştırmanız önerilir.${NC}"
    echo ""
fi

# Python versiyon kontrolü
echo -e "${BLUE}🐍 Python versiyonu kontrol ediliyor...${NC}"
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Python3 bulunamadı! Lütfen Python 3.6+ kurun.${NC}"
    exit 1
fi

# pip kontrolü
echo -e "${BLUE}📦 pip kontrol ediliyor...${NC}"
python3 -m pip --version
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ pip bulunamadı! Lütfen pip kurun.${NC}"
    exit 1
fi

# Sistem paket yöneticisi tespiti
if command -v apt-get &> /dev/null; then
    PACKAGE_MANAGER="apt"
    echo -e "${GREEN}✅ Ubuntu/Debian sistemi tespit edildi${NC}"
elif command -v yum &> /dev/null; then
    PACKAGE_MANAGER="yum"
    echo -e "${GREEN}✅ CentOS/RHEL sistemi tespit edildi${NC}"
elif command -v brew &> /dev/null; then
    PACKAGE_MANAGER="brew"
    echo -e "${GREEN}✅ macOS sistemi tespit edildi${NC}"
else
    PACKAGE_MANAGER="unknown"
    echo -e "${YELLOW}⚠️  Bilinmeyen sistem. Manuel kurulum gerekebilir.${NC}"
fi

# Nmap kurulumu
echo -e "${BLUE}🔍 Nmap kurulumu kontrol ediliyor...${NC}"
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}✅ Nmap zaten kurulu${NC}"
    nmap --version
else
    echo -e "${YELLOW}⚠️  Nmap bulunamadı. Kuruluyor...${NC}"
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get update
            sudo apt-get install -y nmap
            ;;
        "yum")
            sudo yum install -y nmap
            ;;
        "brew")
            brew install nmap
            ;;
        *)
            echo -e "${RED}❌ Nmap manuel olarak kurulmalı: https://nmap.org/download.html${NC}"
            ;;
    esac
fi

# Python kütüphaneleri kurulumu
echo -e "${BLUE}📚 Python kütüphaneleri kuruluyor...${NC}"

# Scapy kurulumu
echo -e "${BLUE}   📦 Scapy kuruluyor...${NC}"
python3 -m pip install --user scapy
if [ $? -eq 0 ]; then
    echo -e "${GREEN}   ✅ Scapy kuruldu${NC}"
else
    echo -e "${RED}   ❌ Scapy kurulumu başarısız${NC}"
    exit 1
fi

# python-nmap kurulumu
echo -e "${BLUE}   📦 python-nmap kuruluyor...${NC}"
python3 -m pip install --user python-nmap
if [ $? -eq 0 ]; then
    echo -e "${GREEN}   ✅ python-nmap kuruldu${NC}"
else
    echo -e "${RED}   ❌ python-nmap kurulumu başarısız${NC}"
    exit 1
fi

# requests kurulumu
echo -e "${BLUE}   📦 requests kuruluyor...${NC}"
python3 -m pip install --user requests
if [ $? -eq 0 ]; then
    echo -e "${GREEN}   ✅ requests kuruldu${NC}"
else
    echo -e "${RED}   ❌ requests kurulumu başarısız${NC}"
    exit 1
fi

# Yetki kontrolü
echo -e "${BLUE}🔐 Yetki kontrolü...${NC}"
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}✅ Root yetkileri mevcut${NC}"
else
    echo -e "${YELLOW}⚠️  Root yetkileri gerekli. Kullanım için 'sudo' kullanın.${NC}"
fi

# Ağ arayüzü kontrolü
echo -e "${BLUE}🌐 Ağ arayüzleri kontrol ediliyor...${NC}"
if command -v ip &> /dev/null; then
    echo -e "${GREEN}✅ ip komutu mevcut${NC}"
    echo "Mevcut ağ arayüzleri:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
elif command -v ifconfig &> /dev/null; then
    echo -e "${GREEN}✅ ifconfig komutu mevcut${NC}"
    echo "Mevcut ağ arayüzleri:"
    ifconfig -a | grep -E "^[a-zA-Z]" | cut -d: -f1
else
    echo -e "${YELLOW}⚠️  Ağ arayüzü komutları bulunamadı${NC}"
fi

# Test çalıştırma
echo -e "${BLUE}🧪 Test çalıştırma...${NC}"
python3 -c "
import scapy
import nmap
import requests
print('✅ Tüm kütüphaneler başarıyla import edildi')
"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Kurulum başarılı!${NC}"
else
    echo -e "${RED}❌ Kurulum testi başarısız${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 Kurulum tamamlandı!${NC}"
echo ""
echo -e "${BLUE}📖 Kullanım örnekleri:${NC}"
echo "  sudo python3 shark.py --auto-interface --duration 300"
echo "  sudo python3 shark.py --interface eth0 --output capture.pcap"
echo "  sudo python3 shark.py --help"
echo ""
echo -e "${YELLOW}⚠️  Hatırlatma: Bu araç yalnızca eğitim amaçlıdır!${NC}"
echo -e "${YELLOW}   Yalnızca kendi sahip olduğunuz ağlarda kullanın.${NC}"
echo ""


