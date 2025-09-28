@echo off
REM Etik Ağ İzleme Aracı - Windows Kurulum Scripti
REM Academic Network Monitor - Windows Installation Script

echo.
echo 🔍 Etik Ağ İzleme Aracı Kurulumu
echo =================================
echo.

REM Uyarı mesajı
echo ⚠️  UYARI: Bu araç yalnızca eğitim amaçlıdır!
echo    Yalnızca kendi sahip olduğunuz ağlarda kullanın.
echo.

REM Python versiyon kontrolü
echo 🐍 Python versiyonu kontrol ediliyor...
python --version
if %errorlevel% neq 0 (
    echo ❌ Python bulunamadı! Lütfen Python 3.6+ kurun.
    echo    https://python.org/downloads/
    pause
    exit /b 1
)

REM pip kontrolü
echo 📦 pip kontrol ediliyor...
python -m pip --version
if %errorlevel% neq 0 (
    echo ❌ pip bulunamadı! Lütfen pip kurun.
    pause
    exit /b 1
)

REM Python kütüphaneleri kurulumu
echo 📚 Python kütüphaneleri kuruluyor...

REM Scapy kurulumu
echo    📦 Scapy kuruluyor...
python -m pip install scapy
if %errorlevel% neq 0 (
    echo    ❌ Scapy kurulumu başarısız
    pause
    exit /b 1
) else (
    echo    ✅ Scapy kuruldu
)

REM python-nmap kurulumu
echo    📦 python-nmap kuruluyor...
python -m pip install python-nmap
if %errorlevel% neq 0 (
    echo    ❌ python-nmap kurulumu başarısız
    pause
    exit /b 1
) else (
    echo    ✅ python-nmap kuruldu
)

REM requests kurulumu
echo    📦 requests kuruluyor...
python -m pip install requests
if %errorlevel% neq 0 (
    echo    ❌ requests kurulumu başarısız
    pause
    exit /b 1
) else (
    echo    ✅ requests kuruldu
)

REM Npcap kontrolü
echo 🔍 Npcap kontrol ediliyor...
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npcap" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Npcap kurulu
) else (
    echo ⚠️  Npcap bulunamadı!
    echo    Lütfen https://npcap.com/ adresinden Npcap kurun.
    echo    WinPcap yerine Npcap kullanın.
)

REM Nmap kontrolü
echo 🔍 Nmap kontrol ediliyor...
nmap --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Nmap kurulu
    nmap --version
) else (
    echo ⚠️  Nmap bulunamadı!
    echo    Lütfen https://nmap.org/download.html adresinden Nmap kurun.
)

REM Test çalıştırma
echo 🧪 Test çalıştırma...
python -c "import scapy; import nmap; import requests; print('✅ Tüm kütüphaneler başarıyla import edildi')"
if %errorlevel% neq 0 (
    echo ❌ Kurulum testi başarısız
    pause
    exit /b 1
) else (
    echo ✅ Kurulum başarılı!
)

echo.
echo 🎉 Kurulum tamamlandı!
echo.
echo 📖 Kullanım örnekleri:
echo   python shark.py --auto-interface --duration 300
echo   python shark.py --interface "Ethernet" --output capture.pcap
echo   python shark.py --help
echo.
echo ⚠️  Hatırlatma: Bu araç yalnızca eğitim amaçlıdır!
echo    Yalnızca kendi sahip olduğunuz ağlarda kullanın.
echo.
echo Windows'ta Administrator yetkileri gerekebilir.
echo.
pause


