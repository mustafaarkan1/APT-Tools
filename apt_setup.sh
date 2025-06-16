#!/bin/bash

# سكريبت تثبيت وإعداد أداة تحليل التهديدات المستمرة والمتطورة
# APT Analyzer Setup Script for Linux

echo "🔧 بدء تثبيت أداة تحليل التهديدات المستمرة والمتطورة"
echo "============================================================="

# التحقق من صلاحيات المدير
if [[ $EUID -ne 0 ]]; then
   echo "❌ يجب تشغيل هذا السكريبت بصلاحيات المدير (sudo)"
   exit 1
fi

# اكتشاف نظام التشغيل
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "❌ لا يمكن اكتشاف نظام التشغيل"
    exit 1
fi

echo "📋 نظام التشغيل: $OS $VER"

# تحديث قوائم الحزم
echo "🔄 تحديث قوائم الحزم..."
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    apt update
    PACKAGE_MANAGER="apt"
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
    if command -v dnf &> /dev/null; then
        dnf update -y
        PACKAGE_MANAGER="dnf"
    else
        yum update -y
        PACKAGE_MANAGER="yum"
    fi
elif [[ "$OS" == *"Arch"* ]]; then
    pacman -Syu --noconfirm
    PACKAGE_MANAGER="pacman"
else
    echo "⚠️  نظام التشغيل غير مدعوم بشكل كامل، سيتم المحاولة باستخدام pip"
fi

# تثبيت Python 3 والأدوات الأساسية
echo "🐍 تثبيت Python 3 والأدوات الأساسية..."
if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
    apt install -y python3 python3-pip python3-dev build-essential libpcap-dev tcpdump
elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
    dnf install -y python3 python3-pip python3-devel gcc libpcap-devel tcpdump
elif [[ "$PACKAGE_MANAGER" == "yum" ]]; then
    yum install -y python3 python3-pip python3-devel gcc libpcap-devel tcpdump
elif [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
    pacman -S --noconfirm python python-pip base-devel libpcap tcpdump
fi

# تثبيت مكتبات Python المطلوبة
echo "📦 تثبيت مكتبات Python المطلوبة..."
pip3 install --upgrade pip
pip3 install scapy pandas numpy scikit-learn joblib

# إنشاء مجلد العمل
WORK_DIR="/opt/apt-analyzer"
echo "📁 إنشاء مجلد العمل: $WORK_DIR"
mkdir -p $WORK_DIR
cd $WORK_DIR

# إنشاء ملف الإعدادات الافتراضي
echo "⚙️  إنشاء ملف الإعدادات..."
cat > apt_config.json << 'EOF'
{
    "email_alerts": {
        "enabled": false,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email": "your-email@gmail.com",
        "sender_password": "your-app-password",
        "recipient_email": "admin@company.com"
    },
    "analysis_settings": {
        "sensitivity": 0.1,
        "time_window": 60,
        "min_packets_for_analysis": 100
    },
    "threat_detection": {
        "enable_dns_analysis": true,
        "enable_port_scan_detection": true,
        "enable_data_exfiltration_detection": true,
        "enable_lateral_movement_detection": true
    },
    "network_settings": {
        "monitor_interfaces": ["eth0", "wlan0"],
        "exclude_private_ips": false,
        "capture_filter": ""
    },
    "logging": {
        "log_level": "INFO",
        "max_log_size": "100MB",
        "log_retention_days": 30
    }
}
EOF

# إنشاء ملف مؤشرات التهديد
echo "🎯 إنشاء ملف مؤشرات التهديد..."
cat > threat_indicators.json << 'EOF'
{
    "malicious_ips": [
        "192.168.1.100",
        "10.0.0.50"
    ],
    "suspicious_domains": [
        "malicious-domain.com",
        "phishing-site.net",
        "c2-server.org"
    ],
    "suspicious_ports": [
        31337, 4444, 5555, 6666, 1234, 12345, 8080, 9999
    ],
    "known_malware_signatures": [
        "suspicious-string-1",
        "malware-pattern-2"
    ]
}
EOF

# إنشاء سكريپت الخدمة systemd
echo "🔧 إنشاء خدمة systemd..."
cat > /etc/systemd/system/apt-analyzer.service << EOF
[Unit]
Description=Advanced Persistent Threat Network Analyzer
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORK_DIR
ExecStart=/usr/bin/python3 $WORK_DIR/apt_analyzer.py -i eth0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# إنشاء سكريپت بدء التشغيل
echo "🚀 إنشاء سكريپت بدء التشغيل..."
cat > start_apt_analyzer.sh << 'EOF'
#!/bin/bash

# سكريپت بدء تشغيل محلل التهديدات المستمرة

echo "🚀 بدء تشغيل محلل التهديدات المستmرة والمتطورة"

# التحقق من الصلاحيات
if [[ $EUID -ne 0 ]]; then
   echo "❌ يجب تشغيل هذا السكريپت بصلاحيات المدير (sudo)"
   exit 1
fi

# التحقق من وجود الملفات المطلوبة
if [[ ! -f "apt_analyzer.py" ]]; then
    echo "❌ ملف apt_analyzer.py غير موجود"
    exit 1
fi

# عرض الواجهات المتاحة
echo "📡 واجهات الشبكة المتاحة:"
python3 apt_analyzer.py --list-interfaces

echo ""
read -p "🔍 اختر واجهة الشبكة للمراقبة (افتراضي: eth0): " interface
interface=${interface:-eth0}

echo "🔄 بدء المراقبة على الواجهة: $interface"
python3 apt_analyzer.py -i $interface
EOF

chmod +x start_apt_analyzer.sh

# إنشاء سكريپت التدريب
echo "🧠 إنشاء سكريپت التدريب..."
cat > train_model.sh << 'EOF'
#!/bin/bash

# سكريپت تدريب نموذج كشف الشذوذ

echo "🧠 تدريب نموذج كشف الشذوذ"

if [[ ! -f "training_data.csv" ]]; then
    echo "📊 إنشاء بيانات تدريب تجريبية..."
    
    # إنشاء بيانات تدريب تجريبية
    python3 << 'PYTHON_EOF'
import pandas as pd
import numpy as np

# إنشاء بيانات تدريب تجريبية
np.random.seed(42)
n_samples = 5000

data = {
    'src_port': np.random.randint(1024, 65535, n_samples),
    'dst_port': np.random.choice([80, 443, 22, 21, 25, 53, 110, 143, 993, 995], n_samples),
    'packet_size': np.random.normal(512, 200, n_samples).astype(int),
    'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
    'timestamp': np.arange(n_samples)
}

# إضافة بعض القيم الشاذة
anomaly_indices = np.random.choice(n_samples, 50, replace=False)
data['packet_size'][anomaly_indices] = np.random.randint(10000, 50000, 50)
data['src_port'][anomaly_indices] = np.random.choice([31337, 4444, 1234], 50)

df = pd.DataFrame(data)
df.to_csv('training_data.csv', index=False)
print("✅ تم إنشاء ملف training_data.csv")
PYTHON_EOF
fi

echo "🏃 بدء تدريب النموذج..."
python3 apt_analyzer.py -t training_data.csv

if [[ -f "apt_model.pkl" ]]; then
    echo "✅ تم تدريب النموذج بنجاح"
    echo "📁 الملفات المحفوظة:"
    ls -la apt_model.pkl apt_scaler.pkl
else
    echo "❌ فشل في تدريب النموذج"
fi
EOF

chmod +x train_model.sh

# إنشاء سكريپت إنتاج التقارير
echo "📋 إنشاء سكريپت إنتاج التقارير..."
cat > generate_report.sh << 'EOF'
#!/bin/bash

# سكريپت إنتاج التقارير

echo "📋 إنتاج تقرير محلل التهديدات"

python3 apt_analyzer.py --report

if [[ -f "apt_report.json" ]]; then
    echo "✅ تم إنتاج التقرير بنجاح"
    echo "📄 محتويات التقرير:"
    cat apt_report.json | python3 -m json.tool
else
    echo "❌ فشل في إنتاج التقرير"
fi

# إنتاج تقرير HTML
if command -v python3 &> /dev/null; then
    python3 << 'PYTHON_EOF'
import json
import datetime

try:
    with open('apt_report.json', 'r', encoding='utf-8') as f:
        report = json.load(f)
    
    html_content = f"""
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <title>تقرير محلل التهديدات المستمرة</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; direction: rtl; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
            .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
            .stats {{ display: flex; justify-content: space-around; }}
            .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
            .alert {{ background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ تقرير محلل التهديدات المستمرة والمتطورة</h1>
            <p>تاريخ التقرير: {report.get('timestamp', 'غير محدد')}</p>
        </div>
        
        <div class="section">
            <h2>📊 إحصائيات عامة</h2>
            <div class="stats">
                <div class="stat-box">
                    <h3>إجمالي الحزم</h3>
                    <p>{report.get('statistics', {}).get('total_packets', 0)}</p>
                </div>
                <div class="stat-box">
                    <h3>الأنشطة المشبوهة</h3>
                    <p>{report.get('statistics', {}).get('suspicious_activities', 0)}</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🤖 حالة النموذج</h2>
            <p>حالة التدريب: {'مدرب' if report.get('model_status', {}).get('is_trained', False) else 'غير مدرب'}</p>
            <p>عينات التدريب: {report.get('model_status', {}).get('training_samples', 0)}</p>
        </div>
        
        <div class="section">
            <h2>⚙️ الإعدادات الحالية</h2>
            <p>حساسية الكشف: {report.get('configuration', {}).get('analysis_settings', {}).get('sensitivity', 'غير محدد')}</p>
            <p>النافذة الزمنية: {report.get('configuration', {}).get('analysis_settings', {}).get('time_window', 'غير محدد')} ثانية</p>
        </div>
    </body>
    </html>
    """
    
    with open('apt_report.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("✅ تم إنتاج التقرير HTML: apt_report.html")
    
except Exception as e:
    print(f"❌ خطأ في إنتاج التقرير HTML: {e}")
PYTHON_EOF
fi
EOF

chmod +x generate_report.sh

# تعيين الصلاحيات
echo "🔐 تعيين الصلاحيات..."
chmod +x apt_analyzer.py
chown -R root:root $WORK_DIR

# إعادة تحميل systemd
systemctl daemon-reload

echo ""
echo "✅ تم تثبيت أداة تحليل التهديدات المستمرة والمتطورة بنجاح!"
echo "============================================================="
echo ""
echo "📁 موقع التثبيت: $WORK_DIR"
echo ""
echo "🚀 طرق التشغيل:"
echo "1️⃣  التشغيل التفاعلي:"
echo "   cd $WORK_DIR && sudo ./start_apt_analyzer.sh"
echo ""
echo "2️⃣  التشغيل كخدمة:"
echo "   sudo systemctl start apt-analyzer"
echo "   sudo systemctl enable apt-analyzer"
echo ""
echo "3️⃣  التشغيل المباشر:"
echo "   sudo python3 $WORK_DIR/apt_analyzer.py -i eth0"
echo ""
echo "🧠 تدريب النموذج:"
echo "   cd $WORK_DIR && sudo ./train_model.sh"
echo ""
echo "📋 إنتاج التقارير:"
echo "   cd $WORK_DIR && ./generate_report.sh"
echo ""
echo "⚙️  تحرير الإعدادات:"
echo "   nano $WORK_DIR/apt_config.json"
echo ""
echo "📜 عرض السجلات:"
echo "   tail -f $WORK_DIR/apt_analyzer.log"
echo "   tail -f $WORK_DIR/alerts.log"
echo ""
echo "🛑 إيقاف الخدمة:"
echo "   sudo systemctl stop apt-analyzer"
echo ""
echo "⚠️  ملاحظات مهمة:"
echo "• تأكد من تعديل إعدادات البريد الإلكتروني في apt_config.json"
echo "• قم بتدريب النموذج باستخدام بيانات شبكتك الحقيقية"
echo "• راجع السجلات بانتظام للتأكد من سلامة التشغيل"
echo "• استخدم واجهة الشبكة الصحيحة (eth0, wlan0, etc.)"
echo ""
echo "🔗 للحصول على المساعدة:"
echo "   python3 $WORK_DIR/apt_analyzer.py --help"