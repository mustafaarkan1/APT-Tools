#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
أداة تحليل التهديدات المستمرة والمتطورة (APT Analyzer) - النسخة المتقدمة
Advanced Persistent Threat Network Analyzer for Linux with Web GUI
"""

import os
import sys
import time
import json
import logging
import argparse
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
import signal
import math
import socket
import tempfile
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from werkzeug.serving import make_server

# إنشاء مجلدات مؤقتة للقوالب
TEMPLATE_DIR = tempfile.mkdtemp(prefix='apt_templates_')
STATIC_DIR = tempfile.mkdtemp(prefix='apt_static_')

# تهيئة تطبيق Flask لواجهة الويب
app = Flask(__name__, static_folder=STATIC_DIR, template_folder=TEMPLATE_DIR)
app.config['SECRET_KEY'] = 'apt_analyzer_secret_key'
socketio = SocketIO(app, async_mode='threading')

class APTWebAnalyzer:
    def __init__(self, interface="eth0", config_file="apt_config.json"):
        """
        تهيئة محلل التهديدات مع دعم واجهة الويب
        """
        self.interface = interface
        self.config_file = config_file
        self.running = False
        self.web_gui_enabled = False
        self.server_thread = None
        self.flask_server = None
        
        # إعداد السجلات
        self.log_file = None
        self.setup_logging()
        
        # تحميل الإعدادات
        self.load_config()
        
        # بيانات التحليل
        self.packet_buffer = deque(maxlen=10000)
        self.connection_stats = defaultdict(self._init_connection_stats)
        self.time_window = 60
        self.features_data = []
        self.alerts_log = deque(maxlen=100)
        
        # نموذج التعلم الآلي
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # إحصائيات الشبكة
        self.network_stats = {
            'total_packets': 0,
            'suspicious_activities': 0,
            'last_analysis': None,
            'protocols': defaultdict(int),
            'top_talkers': defaultdict(int),
            'threat_level': "منخفض"
        }
        
        # خيوط المعالجة
        self.analysis_thread = None
        self.alert_thread = None
        self.threat_tracking_thread = None
        
        # مؤشرات التهديد المعروفة
        self.threat_indicators = {
            'suspicious_domains': set(),
            'malicious_ips': set(),
            'suspicious_ports': {31337, 4444, 5555, 6666, 1234, 12345},
            'dns_tunneling_domains': set(),
            'known_malware_signatures': []
        }
        
        # سلاسل التهديدات
        self.threat_chains = defaultdict(dict)
        
        # أنظمة الخداع
        self.honeypots = {}
        
        self.logger.info("تم تهيئة محلل التهديدات المتقدم مع واجهة الويب")

    def _init_connection_stats(self):
        """تهيئة هيكل إحصائيات الاتصال الموحد"""
        return {
            'ports': set(),
            'timestamps': [],
            'data_sent': [],
            'total_bytes': 0,
            'behavior_score': 0
        }

    def setup_logging(self):
        """إعداد نظام السجلات"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        
        # إنشاء ملف سجل مؤقت بأذونات آمنة
        log_fd, log_path = tempfile.mkstemp(prefix='apt_analyzer_', suffix='.log')
        os.close(log_fd)  # نغلق الواصف لأننا سنفتح الملف لاحقًا
        self.log_file = log_path
        
        # إعداد المسجل
        self.logger = logging.getLogger('APT_Analyzer')
        self.logger.setLevel(logging.INFO)
        
        # معالج للكتابة إلى الملف
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format))
        
        # معالج للكتابة إلى الكونسول
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.logger.info(f"تم إنشاء ملف السجلات: {log_path}")

    def load_config(self):
        """تحميل ملف الإعدادات"""
        default_config = {
            "email_alerts": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "sender_email": "",
                "sender_password": "",
                "recipient_email": ""
            },
            "analysis_settings": {
                "sensitivity": 0.1,
                "time_window": 60,
                "min_packets_for_analysis": 100
            },
            "threat_detection": {
                "enable_dns_analysis": True,
                "enable_port_scan_detection": True,
                "enable_data_exfiltration_detection": True,
                "enable_lateral_movement_detection": True,
                "enable_encrypted_tunnel_detection": True,
                "enable_behavior_analysis": True
            },
            "web_gui": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 5000
            },
            "honeypots": {
                "enabled": False,
                "ports": [21, 22, 80, 443, 3389]
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            else:
                self.config = default_config
                self.save_config()
        except Exception as e:
            self.logger.error(f"خطأ في تحميل الإعدادات: {e}")
            self.config = default_config

    def save_config(self):
        """حفظ ملف الإعدادات"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"خطأ في حفظ الإعدادات: {e}")

    def check_privileges(self):
        """التحقق من صلاحيات المدير"""
        if os.geteuid() != 0:
            self.logger.error("يجب تشغيل الأداة بصلاحيات المدير (sudo)")
            return False
        return True

    def start_web_gui(self):
        """بدء واجهة الويب"""
        if not self.config['web_gui']['enabled']:
            return
            
        self.web_gui_enabled = True
        host = self.config['web_gui']['host']
        port = self.config['web_gui']['port']
        
        def run_flask():
            self.logger.info(f"بدء واجهة الويب على http://{host}:{port}")
            self.flask_server = make_server(host, port, app)
            self.flask_server.serve_forever()
        
        self.server_thread = threading.Thread(target=run_flask, daemon=True)
        self.server_thread.start()
        
        # بدء أنظمة الخداع إذا كانت مفعلة
        if self.config['honeypots']['enabled']:
            self.deploy_honeypot()
        
        # بدء تتبع التهديدات
        self.start_threat_tracking()

    def stop_web_gui(self):
        """إيقاف واجهة الويب"""
        if self.flask_server:
            self.flask_server.shutdown()
        self.web_gui_enabled = False

    def calculate_entropy(self, data):
        """حساب إنتروبيا البيانات"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
                
        return entropy

    def detect_encrypted_tunneling(self, packet):
        """كشف الأنفاق المشفرة"""
        try:
            if packet.haslayer(TCP):
                payload = bytes(packet[TCP].payload)
                
                # تحليل خصائص التشفير
                entropy = self.calculate_entropy(payload)
                size = len(payload)
                
                # قواعد كشف الأنفاق المشفرة
                if entropy > 7.5 and size > 512:
                    return True
                    
            return False
        except Exception as e:
            self.logger.error(f"خطأ في كشف التشفير: {e}")
            return False

    def extract_packet_features(self, packet):
        """استخراج السمات من الحزمة"""
        features = {
            'timestamp': time.time(),
            'src_ip': '',
            'dst_ip': '',
            'protocol': '',
            'src_port': 0,
            'dst_port': 0,
            'packet_size': len(packet),
            'flags': '',
            'dns_query': '',
            'http_method': '',
            'is_suspicious': False,
            'encrypted_tunnel': False
        }
        
        try:
            if IP in packet:
                features['src_ip'] = packet[IP].src
                features['dst_ip'] = packet[IP].dst
                features['protocol'] = packet[IP].proto
                
                # تحليل بروتوكول TCP
                if TCP in packet:
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                    features['flags'] = str(packet[TCP].flags)
                    features['protocol'] = 'TCP'
                    
                    # فحص المنافذ المشبوهة
                    if (features['dst_port'] in self.threat_indicators['suspicious_ports'] or
                        features['src_port'] in self.threat_indicators['suspicious_ports']):
                        features['is_suspicious'] = True
                
                # تحليل بروتوكول UDP
                elif UDP in packet:
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport
                    features['protocol'] = 'UDP'
                
                # تحليل استعلامات DNS
                if DNS in packet and DNSQR in packet:
                    features['dns_query'] = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    # فحص النطاقات المشبوهة
                    if any(domain in features['dns_query'] for domain in self.threat_indicators['suspicious_domains']):
                        features['is_suspicious'] = True
                
                # تحليل طلبات HTTP
                if HTTPRequest in packet:
                    features['http_method'] = packet[HTTPRequest].Method.decode('utf-8', errors='ignore')
                
                # فحص عناوين IP المشبوهة
                if (features['src_ip'] in self.threat_indicators['malicious_ips'] or
                    features['dst_ip'] in self.threat_indicators['malicious_ips']):
                    features['is_suspicious'] = True
                
                # كشف الأنفاق المشفرة
                if self.config['threat_detection']['enable_encrypted_tunnel_detection']:
                    features['encrypted_tunnel'] = self.detect_encrypted_tunneling(packet)
                    
        except Exception as e:
            self.logger.debug(f"خطأ في استخراج سمات الحزمة: {e}")
        
        return features

    def detect_port_scan(self, src_ip, time_window=30):
        """كشف مسح المنافذ"""
        current_time = time.time()
        stats = self.connection_stats[src_ip]
        
        # إزالة الطوابع الزمنية القديمة
        stats['timestamps'] = [
            ts for ts in stats['timestamps']
            if current_time - ts <= time_window
        ]
        
        # إذا كان هناك أكثر من 10 منافذ مختلفة في النافذة الزمنية
        if len(stats['ports']) > 10:
            return True
        
        return False

    def detect_dns_tunneling(self, dns_query):
        """كشف تهريب البيانات عبر DNS"""
        if not dns_query:
            return False
        
        # فحص الاستعلامات الطويلة أو غير الطبيعية
        if (len(dns_query) > 50 or
            dns_query.count('.') > 5 or
            any(char.isdigit() for char in dns_query.replace('.', '')) and len(dns_query) > 30):
            return True
        
        return False

    def detect_data_exfiltration(self, src_ip, packet_size, time_window=300):
        """كشف تسرب البيانات"""
        current_time = time.time()
        stats = self.connection_stats[src_ip]

        # إضافة البيانات الحالية
        stats['data_sent'].append({
            'timestamp': current_time,
            'size': packet_size
        })

        # تنظيف البيانات القديمة
        stats['data_sent'] = [
            data for data in stats['data_sent']
            if current_time - data['timestamp'] <= time_window
        ]

        # حساب إجمالي البيانات المرسلة
        total_bytes = sum(data['size'] for data in stats['data_sent'])

        # إذا تم إرسال أكثر من 100 ميجابايت في 5 دقائق
        if total_bytes > 100 * 1024 * 1024:
            return True

        return False

    def track_threat_chain(self, alert):
        """تتبع سلسلة التهديدات"""
        if alert['src_ip'] not in self.threat_chains:
            self.threat_chains[alert['src_ip']] = {
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'activities': [],
                'risk_score': 0
            }
        
        chain = self.threat_chains[alert['src_ip']]
        chain['last_seen'] = datetime.now().isoformat()
        chain['activities'].append(alert)
        
        # تحديث درجة الخطورة
        if alert['severity'] == 'عالي':
            chain['risk_score'] += 10
        elif alert['severity'] == 'متوسط':
            chain['risk_score'] += 5
        else:
            chain['risk_score'] += 2
            
        # تحديث مستوى التهديد العام
        if chain['risk_score'] > 30:
            self.network_stats['threat_level'] = "عالي"
        elif chain['risk_score'] > 15:
            self.network_stats['threat_level'] = "متوسط"
        
        # إرسال تحديث إلى واجهة الويب
        if self.web_gui_enabled:
            socketio.emit('threat_update', {
                'ip': alert['src_ip'],
                'risk_score': chain['risk_score'],
                'last_activity': alert['type']
            })

    def deploy_honeypot(self):
        """نشر أنظمة خداع (Honeypots)"""
        if not self.config['honeypots']['enabled']:
            return
            
        try:
            # إنشاء منافذ خداع
            for port in self.config['honeypots']['ports']:
                threading.Thread(
                    target=self.create_honeypot,
                    args=(port,),
                    daemon=True
                ).start()
                self.logger.info(f"تم نشر منفذ خداع على المنفذ {port}")
        except Exception as e:
            self.logger.error(f"خطأ في نشر أنظمة الخداع: {e}")

    def create_honeypot(self, port):
        """إنشاء منفذ خداع"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            
            while self.running:
                client, addr = server.accept()
                ip = addr[0]
                
                self.logger.warning(f"⛳ اتصال مشبوه بمنفذ الخداع {port} من {ip}")
                
                # تسجيل التفاعل مع الخداع
                alert = {
                    'type': 'تفاعل مع نظام خداع',
                    'src_ip': ip,
                    'dst_port': port,
                    'description': f'اتصال مشبوه بنظام الخداع على المنفذ {port}',
                    'severity': 'متوسط',
                    'timestamp': datetime.now().isoformat()
                }
                
                # إضافة إلى سجل التنبيهات
                self.alerts_log.append(alert)
                
                # تتبع التهديد
                self.track_threat_chain(alert)
                
                # إرسال تنبيه إلى واجهة الويب
                if self.web_gui_enabled:
                    socketio.emit('new_alert', alert)
                    socketio.emit('honeypot_interaction', {
                        'ip': ip,
                        'port': port,
                        'timestamp': datetime.now().isoformat()
                    })
                
                # إرسال بيانات وهمية
                client.send(b"220 Fake Service Ready\r\n")
                time.sleep(1)
                client.close()
        except Exception as e:
            self.logger.error(f"خطأ في منفذ الخداع {port}: {e}")

    def start_threat_tracking(self):
        """بدء تتبع التهديدات"""
        self.threat_tracking_thread = threading.Thread(target=self.temporal_analysis, daemon=True)
        self.threat_tracking_thread.start()

    def temporal_analysis(self):
        """تحليل الأنماط الزمنية للتهديدات"""
        while self.running:
            try:
                # تحليل الأنشطة كل 5 دقائق
                time.sleep(300)
                
                # كشف الهجمات الموزعة
                self.detect_ddos_patterns()
                
                # كشف المسح الزمني
                self.detect_time_based_scans()
                
            except Exception as e:
                self.logger.error(f"خطأ في التحليل الزمني: {e}")

    def detect_ddos_patterns(self):
        """كشف أنماط الهجمات الموزعة"""
        # تحليل توزيع المصادر والأهداف
        src_distribution = defaultdict(int)
        dst_distribution = defaultdict(int)
        
        for features in self.packet_buffer:
            src_distribution[features['src_ip']] += 1
            dst_distribution[features['dst_ip']] += 1
        
        # كشف هجمات DDoS
        if len(src_distribution) > 1000 and len(dst_distribution) < 10:
            alert = {
                'type': 'هجوم موزع',
                'description': 'تم اكتشاف هجوم DDoS محتمل',
                'severity': 'عالي',
                'timestamp': datetime.now().isoformat()
            }
            
            self.alerts_log.append(alert)
            self.network_stats['suspicious_activities'] += 1
            
            if self.web_gui_enabled:
                socketio.emit('new_alert', alert)

    def analyze_packet_features(self, features_batch):
        """تحليل مجموعة من سمات الحزم"""
        if not features_batch or not self.is_trained:
            return []
        
        try:
            # إعداد البيانات للتحليل
            df = pd.DataFrame(features_batch)
            
            # اختيار السمات الرقمية
            numeric_features = ['src_port', 'dst_port', 'packet_size']
            analysis_data = df[numeric_features].fillna(0)
            
            # تطبيق التطبيع
            scaled_data = self.scaler.transform(analysis_data)
            
            # التنبؤ باستخدام النموذج
            predictions = self.model.predict(scaled_data)
            anomaly_scores = self.model.decision_function(scaled_data)
            
            # إرجاع النتائج
            results = []
            for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
                if pred == -1:  # شذوذ مكتشف
                    results.append({
                        'index': i,
                        'anomaly_score': float(score),
                        'features': features_batch[i],
                        'threat_level': self.classify_threat_level(score)
                    })
            
            return results
            
        except Exception as e:
            self.logger.error(f"خطأ في تحليل السمات: {e}")
            return []

    def classify_threat_level(self, anomaly_score):
        """تصنيف مستوى التهديد"""
        if anomaly_score < -0.3:
            return "عالي"
        elif anomaly_score < -0.1:
            return "متوسط"
        else:
            return "منخفض"

    def packet_handler(self, packet):
        """معالج الحزم الواردة"""
        try:
            # استخراج السمات
            features = self.extract_packet_features(packet)
            
            # إضافة إلى المخزن المؤقت
            self.packet_buffer.append(features)
            
            # تحديث الإحصائيات
            self.network_stats['total_packets'] += 1
            self.network_stats['protocols'][features['protocol']] += 1
            self.network_stats['top_talkers'][features['src_ip']] += 1
            
            # فحص التهديدات الفورية
            self.immediate_threat_detection(features)
            
        except Exception as e:
            self.logger.debug(f"خطأ في معالجة الحزمة: {e}")

    def immediate_threat_detection(self, features):
        """كشف التهديدات الفوري"""
        alerts = []
        
        try:
            # فحص مسح المنافذ
            if self.config['threat_detection']['enable_port_scan_detection']:
                if features['protocol'] == 'TCP' and features['dst_port'] != 0:
                    src_ip = features['src_ip']
                    stats = self.connection_stats[src_ip]
                    
                    stats['ports'].add(features['dst_port'])
                    stats['timestamps'].append(features['timestamp'])
                    
                    if self.detect_port_scan(src_ip):
                        alerts.append({
                            'type': 'مسح المنافذ',
                            'src_ip': src_ip,
                            'description': f'تم اكتشاف مسح منافذ من {src_ip}',
                            'severity': 'عالي'
                        })
            
            # فحص تهريب DNS
            if (self.config['threat_detection']['enable_dns_analysis'] and 
                features['dns_query']):
                if self.detect_dns_tunneling(features['dns_query']):
                    alerts.append({
                        'type': 'تهريب DNS',
                        'src_ip': features['src_ip'],
                        'dns_query': features['dns_query'],
                        'description': f'استعلام DNS مشبوه: {features["dns_query"]}',
                        'severity': 'متوسط'
                    })
            
            # فحص تسرب البيانات
            if self.config['threat_detection']['enable_data_exfiltration_detection']:
                if self.detect_data_exfiltration(features['src_ip'], features['packet_size']):
                    alerts.append({
                        'type': 'تسرب البيانات',
                        'src_ip': features['src_ip'],
                        'description': f'كمية بيانات كبيرة من {features["src_ip"]}',
                        'severity': 'عالي'
                    })
            
            # إرسال التنبيهات
            for alert in alerts:
                self.send_alert(alert)
                self.network_stats['suspicious_activities'] += 1
                
        except Exception as e:
            self.logger.error(f"خطأ في كشف التهديدات الفوري: {e}")

    def send_alert(self, alert):
        """إرسال تنبيه"""
        try:
            # إضافة الطابع الزمني
            alert['timestamp'] = datetime.now().isoformat()
            
            # طباعة التنبيه
            alert_msg = f"🚨 تنبيه أمني: {alert['type']} - {alert['description']}"
            print(f"\n{alert_msg}")
            self.logger.warning(alert_msg)
            
            # إضافة إلى سجل التنبيهات
            self.alerts_log.append(alert)
            
            # تتبع سلسلة التهديد
            self.track_threat_chain(alert)
            
            # إرسال إلى واجهة الويب
            if self.web_gui_enabled:
                socketio.emit('new_alert', alert)
            
            # حفظ التنبيه في ملف
            alert_fd, alert_path = tempfile.mkstemp(prefix='apt_alerts_', suffix='.log')
            with os.fdopen(alert_fd, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert, ensure_ascii=False) + '\n')
            
            # إرسال بريد إلكتروني إذا كان مفعلاً
            if self.config['email_alerts']['enabled']:
                self.send_email_alert(alert)
                
        except Exception as e:
            self.logger.error(f"خطأ في إرسال التنبيه: {e}")

    def send_email_alert(self, alert):
        """إرسال تنبيه عبر البريد الإلكتروني"""
        try:
            if not all([
                self.config['email_alerts']['sender_email'],
                self.config['email_alerts']['sender_password'],
                self.config['email_alerts']['recipient_email']
            ]):
                return
            
            msg = MIMEMultipart()
            msg['From'] = self.config['email_alerts']['sender_email']
            msg['To'] = self.config['email_alerts']['recipient_email']
            msg['Subject'] = f"تنبيه أمني: {alert['type']}"
            
            body = f"""
            تم اكتشاف نشاط مشبوه في الشبكة:
            
            نوع التهديد: {alert['type']}
            الوصف: {alert['description']}
            مستوى الخطورة: {alert['severity']}
            الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            يرجى اتخاذ الإجراءات اللازمة فوراً.
            """
            
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            server = smtplib.SMTP(
                self.config['email_alerts']['smtp_server'],
                self.config['email_alerts']['smtp_port']
            )
            server.starttls()
            server.login(
                self.config['email_alerts']['sender_email'],
                self.config['email_alerts']['sender_password']
            )
            
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            self.logger.error(f"خطأ في إرسال البريد الإلكتروني: {e}")

    def train_model(self, training_data_file=None):
        """تدريب نموذج كشف الشذوذ"""
        try:
            if training_data_file and os.path.exists(training_data_file):
                # تحميل بيانات التدريب من ملف
                df = pd.read_csv(training_data_file)
            else:
                # استخدام البيانات المجمعة حالياً
                if len(self.features_data) < 1000:
                    self.logger.warning("بيانات التدريب غير كافية، يحتاج إلى 1000 عينة على الأقل")
                    return False
                
                df = pd.DataFrame(list(self.features_data))
            
            # اختيار السمات للتدريب
            numeric_features = ['src_port', 'dst_port', 'packet_size']
            training_data = df[numeric_features].fillna(0)
            
            # تطبيع البيانات
            scaled_data = self.scaler.fit_transform(training_data)
            
            # تدريب نموذج Isolation Forest
            self.model = IsolationForest(
                contamination=self.config['analysis_settings']['sensitivity'],
                random_state=42,
                n_estimators=100
            )
            
            self.model.fit(scaled_data)
            self.is_trained = True
            
            # حفظ النموذج
            joblib.dump(self.model, 'apt_model.pkl')
            joblib.dump(self.scaler, 'apt_scaler.pkl')
            
            self.logger.info("تم تدريب النموذج بنجاح")
            return True
            
        except Exception as e:
            self.logger.error(f"خطأ في تدريب النموذج: {e}")
            return False

    def load_model(self):
        """تحميل النموذج المدرب"""
        try:
            if os.path.exists('apt_model.pkl') and os.path.exists('apt_scaler.pkl'):
                self.model = joblib.load('apt_model.pkl')
                self.scaler = joblib.load('apt_scaler.pkl')
                self.is_trained = True
                self.logger.info("تم تحميل النموذج المدرب")
                return True
        except Exception as e:
            self.logger.error(f"خطأ في تحميل النموذج: {e}")
        
        return False

    def analysis_worker(self):
        """خيط تحليل البيانات"""
        while self.running:
            try:
                if len(self.packet_buffer) >= self.config['analysis_settings']['min_packets_for_analysis']:
                    # استخراج البيانات للتحليل
                    features_batch = list(self.packet_buffer)
                    self.packet_buffer.clear()
                    
                    # إضافة إلى بيانات التدريب
                    self.features_data.extend(features_batch)
                    
                    # تحليل الشذوذ إذا كان النموذج مدرباً
                    if self.is_trained:
                        anomalies = self.analyze_packet_features(features_batch)
                        
                        for anomaly in anomalies:
                            alert = {
                                'type': 'شذوذ في الشبكة',
                                'src_ip': anomaly['features']['src_ip'],
                                'dst_ip': anomaly['features']['dst_ip'],
                                'description': f'نشاط غير طبيعي مكتشف (النتيجة: {anomaly["anomaly_score"]:.3f})',
                                'severity': anomaly['threat_level']
                            }
                            self.send_alert(alert)
                
                time.sleep(self.time_window)
                
            except Exception as e:
                self.logger.error(f"خطأ في خيط التحليل: {e}")
                time.sleep(5)

    def start_capture(self):
        """بدء التقاط الحزم"""
        if not self.check_privileges():
            return False
        
        self.running = True
        
        # بدء خيط التحليل
        self.analysis_thread = threading.Thread(target=self.analysis_worker)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        
        # تحميل النموذج إذا كان متوفراً
        self.load_model()
        
        # بدء واجهة الويب
        if self.config['web_gui']['enabled']:
            self.start_web_gui()
        
        try:
            self.logger.info(f"🔍 بدء مراقبة الشبكة على الواجهة: {self.interface}")
            
            # بدء التقاط الحزم
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda x: not self.running,
                store=0
            )
            
        except KeyboardInterrupt:
            self.logger.info("\n⏹️  توقف التقاط الحزم...")
            self.stop_capture()
        except Exception as e:
            self.logger.error(f"خطأ في التقاط الحزم: {e}")
            return False
        
        return True

    def stop_capture(self):
        """إيقاف التقاط الحزم"""
        self.running = False
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        
        if self.web_gui_enabled:
            self.stop_web_gui()
        
        self.print_statistics()

    def print_statistics(self):
        """طباعة إحصائيات الجلسة"""
        print(f"\n📊 إحصائيات الجلسة:")
        print(f"إجمالي الحزم: {self.network_stats['total_packets']}")
        print(f"الأنشطة المشبوهة: {self.network_stats['suspicious_activities']}")
        
        print(f"\n🔀 البروتوكولات:")
        for protocol, count in sorted(self.network_stats['protocols'].items(), 
                                    key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {protocol}: {count}")
        
        print(f"\n💬 أكثر المتحدثين:")
        for ip, count in sorted(self.network_stats['top_talkers'].items(), 
                              key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")

    def generate_report(self, output_file="apt_report.json"):
        """إنتاج تقرير مفصل"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'statistics': self.network_stats,
                'configuration': self.config,
                'model_status': {
                    'is_trained': self.is_trained,
                    'training_samples': len(self.features_data)
                },
                'threat_indicators': {
                    'suspicious_domains_count': len(self.threat_indicators['suspicious_domains']),
                    'malicious_ips_count': len(self.threat_indicators['malicious_ips']),
                    'suspicious_ports': list(self.threat_indicators['suspicious_ports'])
                },
                'threat_chains': dict(self.threat_chains)
            }
            
            # محاولة الكتابة إلى الملف المطلوب
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=4, ensure_ascii=False)
                self.logger.info(f"تم إنتاج التقرير: {output_file}")
            except PermissionError:
                # إذا فشلت، إنشاء ملف مؤقت
                report_fd, report_path = tempfile.mkstemp(prefix='apt_report_', suffix='.json')
                with os.fdopen(report_fd, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=4, ensure_ascii=False)
                self.logger.info(f"تم إنتاج التقرير في ملف مؤقت: {report_path}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"خطأ في إنتاج التقرير: {e}")
            return False

# تعريفات HTML
HTML_TEMPLATES = {
    'dashboard.html': '''
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>محلل التهديدات المستمرة - لوحة التحكم</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #2c3e50;
                --secondary: #3498db;
                --danger: #e74c3c;
                --warning: #f39c12;
                --success: #27ae60;
                --dark: #34495e;
                --light: #ecf0f1;
            }
            
            body {
                font-family: 'Tajawal', sans-serif;
                background-color: #f5f7fa;
                padding-top: 20px;
                padding-bottom: 50px;
            }
            
            .card {
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                margin-bottom: 20px;
                border: none;
            }
            
            .card-header {
                background-color: var(--primary);
                color: white;
                border-radius: 10px 10px 0 0 !important;
                font-weight: bold;
            }
            
            .stat-card {
                text-align: center;
                padding: 15px;
            }
            
            .stat-number {
                font-size: 2.5rem;
                font-weight: bold;
            }
            
            .alert-card {
                max-height: 400px;
                overflow-y: auto;
            }
            
            .alert-item {
                border-left: 4px solid;
                padding: 10px;
                margin-bottom: 10px;
                background-color: white;
                border-radius: 5px;
            }
            
            .alert-high {
                border-left-color: var(--danger);
            }
            
            .alert-medium {
                border-left-color: var(--warning);
            }
            
            .alert-low {
                border-left-color: var(--secondary);
            }
            
            .threat-level {
                padding: 5px 15px;
                border-radius: 20px;
                font-weight: bold;
                color: white;
            }
            
            .threat-high {
                background-color: var(--danger);
            }
            
            .threat-medium {
                background-color: var(--warning);
            }
            
            .threat-low {
                background-color: var(--success);
            }
            
            .btn-primary {
                background-color: var(--primary);
                border-color: var(--primary);
            }
            
            .btn-stop {
                background-color: var(--danger);
                border-color: var(--danger);
            }
            
            .status-indicator {
                display: inline-block;
                width: 15px;
                height: 15px;
                border-radius: 50%;
                margin-right: 8px;
            }
            
            .status-active {
                background-color: var(--success);
            }
            
            .status-inactive {
                background-color: var(--danger);
            }
        </style>
    </head>
    <body>
        <div class="container-fluid">
            <!-- شريط العنوان -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div>
                                <h3><i class="fas fa-shield-alt me-2"></i>محلل التهديدات المستمرة والمتطورة</h3>
                            </div>
                            <div>
                                <span class="me-2">حالة النظام:</span>
                                <span id="system-status">
                                    <span class="status-indicator status-inactive"></span>
                                    متوقف
                                </span>
                                <button id="start-btn" class="btn btn-primary btn-sm ms-3">
                                    <i class="fas fa-play"></i> بدء المراقبة
                                </button>
                                <button id="stop-btn" class="btn btn-stop btn-sm ms-2" disabled>
                                    <i class="fas fa-stop"></i> إيقاف
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <!-- الإحصائيات الرئيسية -->
                <div class="col-md-3">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-bar me-2"></i>إحصائيات الشبكة
                        </div>
                        <div class="card-body">
                            <div class="stat-card">
                                <div class="stat-number" id="total-packets">0</div>
                                <div class="text-muted">إجمالي الحزم</div>
                            </div>
                            <hr>
                            <div class="stat-card">
                                <div class="stat-number" id="suspicious-activities">0</div>
                                <div class="text-muted">أنشطة مشبوهة</div>
                            </div>
                            <hr>
                            <div class="stat-card">
                                <div class="d-flex justify-content-between align-items-center">
                                    <span>مستوى التهديد:</span>
                                    <span id="threat-level" class="threat-level threat-low">منخفض</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-network-wired me-2"></i>الواجهة الحالية
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label class="form-label">اختر واجهة الشبكة:</label>
                                <select id="interface-select" class="form-select">
                                    {% for iface in interfaces %}
                                    <option value="{{ iface }}" {% if iface == current_interface %}selected{% endif %}>{{ iface }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <button id="update-interface" class="btn btn-primary w-100">
                                تحديث الواجهة
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- التنبيهات الحديثة -->
                <div class="col-md-5">
                    <div class="card alert-card">
                        <div class="card-header">
                            <i class="fas fa-bell me-2"></i>آخر التنبيهات
                        </div>
                        <div class="card-body" id="alerts-container">
                            {% for alert in alerts %}
                            <div class="alert-item alert-{{ 'high' if alert.severity == 'عالي' else 'medium' if alert.severity == 'متوسط' else 'low' }}">
                                <div class="d-flex justify-content-between">
                                    <strong>{{ alert.type }}</strong>
                                    <small>{{ alert.timestamp }}</small>
                                </div>
                                <div>{{ alert.description }}</div>
                                <div class="text-end">
                                    <span class="badge bg-{{ 'danger' if alert.severity == 'عالي' else 'warning' if alert.severity == 'متوسط' else 'primary' }}">
                                        {{ alert.severity }}
                                    </span>
                                </div>
                            </div>
                            {% else %}
                            <div class="text-center text-muted py-4">
                                لا توجد تنبيهات حالياً
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
                
                <!-- سلاسل التهديدات -->
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-link me-2"></i>سلاسل التهديدات النشطة
                        </div>
                        <div class="card-body" id="threat-chains-container">
                            {% if threat_chains %}
                                {% for chain in threat_chains %}
                                <div class="alert-item">
                                    <div class="d-flex justify-content-between">
                                        <strong>{{ chain.src_ip }}</strong>
                                        <span class="badge bg-danger">خطورة عالية</span>
                                    </div>
                                    <div class="mt-2">
                                        <small>آخر نشاط: {{ chain.last_activity }}</small>
                                    </div>
                                    <div class="progress mt-2" style="height: 10px;">
                                        <div class="progress-bar bg-danger" role="progressbar" 
                                            style="width: {{ chain.risk_score }}%;" 
                                            aria-valuenow="{{ chain.risk_score }}" 
                                            aria-valuemin="0" 
                                            aria-valuemax="100">
                                        </div>
                                    </div>
                                </div>
                                {% endfor %}
                            {% else %}
                                <div class="text-center text-muted py-4">
                                    لا توجد سلاسل تهديدات نشطة
                                </div>
                            {% endif %}
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <i class="fas fa-chart-pie me-2"></i>أكثر المتحدثين
                        </div>
                        <div class="card-body">
                            {% for talker in top_talkers %}
                            <div class="d-flex justify-content-between mb-2">
                                <span>{{ talker[0] }}</span>
                                <span class="badge bg-primary">{{ talker[1] }}</span>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
        <script>
            const socket = io();
            
            // تحديث حالة النظام
            socket.on('status_update', function(data) {
                const statusElement = document.getElementById('system-status');
                const statusIndicator = statusElement.querySelector('.status-indicator');
                const startBtn = document.getElementById('start-btn');
                const stopBtn = document.getElementById('stop-btn');
                
                if (data.status) {
                    statusElement.innerHTML = '<span class="status-indicator status-active"></span> نشط';
                    startBtn.disabled = true;
                    stopBtn.disabled = false;
                } else {
                    statusElement.innerHTML = '<span class="status-indicator status-inactive"></span> متوقف';
                    startBtn.disabled = false;
                    stopBtn.disabled = true;
                }
            });
            
            // تحديث الإحصائيات
            socket.on('stats_update', function(data) {
                document.getElementById('total-packets').textContent = data.total_packets;
                document.getElementById('suspicious-activities').textContent = data.suspicious_activities;
                
                // تحديث مستوى التهديد
                const threatLevel = document.getElementById('threat-level');
                threatLevel.textContent = data.threat_level;
                threatLevel.className = 'threat-level ';
                
                if (data.threat_level === 'عالي') {
                    threatLevel.classList.add('threat-high');
                } else if (data.threat_level === 'متوسط') {
                    threatLevel.classList.add('threat-medium');
                } else {
                    threatLevel.classList.add('threat-low');
                }
            });
            
            // استقبال تنبيه جديد
            socket.on('new_alert', function(alert) {
                const alertsContainer = document.getElementById('alerts-container');
                
                const alertClass = alert.severity === 'عالي' ? 'alert-high' : 
                                 alert.severity === 'متوسط' ? 'alert-medium' : 'alert-low';
                
                const alertElement = document.createElement('div');
                alertElement.className = `alert-item ${alertClass}`;
                alertElement.innerHTML = `
                    <div class="d-flex justify-content-between">
                        <strong>${alert.type}</strong>
                        <small>${alert.timestamp}</small>
                    </div>
                    <div>${alert.description}</div>
                    <div class="text-end">
                        <span class="badge bg-${alert.severity === 'عالي' ? 'danger' : 
                                              alert.severity === 'متوسط' ? 'warning' : 'primary'}">
                            ${alert.severity}
                        </span>
                    </div>
                `;
                
                alertsContainer.prepend(alertElement);
            });
            
            // بدء المراقبة
            document.getElementById('start-btn').addEventListener('click', function() {
                const interface = document.getElementById('interface-select').value;
                
                fetch('/start_capture', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `interface=${interface}`
                });
            });
            
            // إيقاف المراقبة
            document.getElementById('stop-btn').addEventListener('click', function() {
                fetch('/stop_capture');
            });
            
            // تحديث الواجهة
            document.getElementById('update-interface').addEventListener('click', function() {
                const interface = document.getElementById('interface-select').value;
                fetch('/update_interface', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `interface=${interface}`
                });
            });
        </script>
    </body>
    </html>
    '''
}

# إنشاء ملفات القوالب في المجلد المؤقت
try:
    for template_name, content in HTML_TEMPLATES.items():
        template_path = os.path.join(TEMPLATE_DIR, template_name)
        os.makedirs(os.path.dirname(template_path), exist_ok=True)
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(content)
        # منح صلاحيات كافية للملف
        os.chmod(template_path, 0o666)
except Exception as e:
    print(f"خطأ في إنشاء القوالب: {e}")

# --- واجهة الويب باستخدام Flask ---

@app.route('/')
def dashboard():
    """لوحة التحكم الرئيسية"""
    stats = analyzer.network_stats
    stats['threat_chains'] = len(analyzer.threat_chains)
    
    # الحصول على آخر 10 تنبيهات
    alerts = list(analyzer.alerts_log)[-10:]
    
    # الحصول على أفضل 5 متحدثين
    top_talkers = sorted(analyzer.network_stats['top_talkers'].items(), 
                         key=lambda x: x[1], reverse=True)[:5]
    
    # الحصول على سلاسل التهديدات عالية الخطورة
    high_risk_chains = []
    for ip, chain in analyzer.threat_chains.items():
        if chain.get('risk_score', 0) > 20:
            chain['src_ip'] = ip
            high_risk_chains.append(chain)
    
    # الحصول على واجهات الشبكة المتاحة
    try:
        interfaces = scapy.get_if_list()
    except:
        interfaces = ['eth0', 'wlan0']
    
    return render_template('dashboard.html', 
                           stats=stats, 
                           alerts=alerts,
                           top_talkers=top_talkers,
                           threat_chains=high_risk_chains,
                           interfaces=interfaces,
                           current_interface=analyzer.interface)

@app.route('/start_capture', methods=['POST'])
def start_capture_route():
    """بدء عملية المراقبة"""
    interface = request.form.get('interface', 'eth0')
    analyzer.interface = interface
    
    # بدء التقاط الحزم في خيط منفصل
    capture_thread = threading.Thread(target=analyzer.start_capture, daemon=True)
    capture_thread.start()
    
    return jsonify({
        'status': 'success',
        'message': f'تم بدء المراقبة على الواجهة {interface}'
    })

@app.route('/stop_capture')
def stop_capture_route():
    """إيقاف عملية المراقبة"""
    analyzer.stop_capture()
    return jsonify({
        'status': 'success',
        'message': 'تم إيقاف المراقبة'
    })

@app.route('/alerts')
def get_alerts():
    """الحصول على التنبيهات"""
    return jsonify(list(analyzer.alerts_log))

@app.route('/threat_chains')
def get_threat_chains():
    """الحصول على سلاسل التهديدات"""
    return jsonify(analyzer.threat_chains)

@app.route('/config', methods=['GET', 'POST'])
def manage_config():
    """إدارة الإعدادات"""
    if request.method == 'POST':
        # تحديث الإعدادات
        new_config = request.json
        analyzer.config.update(new_config)
        analyzer.save_config()
        return jsonify({'status': 'success'})
    
    return jsonify(analyzer.config)

@app.route('/report')
def generate_report_route():
    """إنشاء وتحميل تقرير"""
    report_file = "apt_report.json"
    if analyzer.generate_report(report_file):
        return send_file(report_file, as_attachment=True)
    else:
        return jsonify({'status': 'error', 'message': 'فشل في إنتاج التقرير'})

@app.route('/network_stats')
def get_network_stats():
    """الحصول على إحصائيات الشبكة"""
    return jsonify(analyzer.network_stats)

@app.route('/update_interface', methods=['POST'])
def update_interface():
    """تحديث واجهة الشبكة"""
    interface = request.form.get('interface', 'eth0')
    analyzer.interface = interface
    return jsonify({
        'status': 'success',
        'message': f'تم تحديث الواجهة إلى {interface}'
    })

@socketio.on('connect')
def handle_connect():
    """معالجة اتصال العميل"""
    emit('status_update', {'status': analyzer.running, 'interface': analyzer.interface})

# الدالة الرئيسية لتشغيل النظام
def main():
    """الدالة الرئيسية"""
    # تسجيل معالج الإشارات
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # إعداد الخيارات
    parser = argparse.ArgumentParser(
        description='أداة تحليل التهديدات المستمرة والمتطورة مع واجهة الويب',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-i', '--interface',
        default='eth0',
        help='واجهة الشبكة للمراقبة (افتراضي: eth0)'
    )
    
    parser.add_argument(
        '-c', '--config',
        default='apt_config.json',
        help='ملف الإعدادات (افتراضي: apt_config.json)'
    )
    
    parser.add_argument(
        '-t', '--train',
        metavar='FILE',
        help='تدريب النموذج باستخدام ملف CSV'
    )
    
    parser.add_argument(
        '-r', '--report',
        action='store_true',
        help='إنتاج تقرير وإنهاء البرنامج'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='عرض واجهات الشبكة المتاحة'
    )
    
    parser.add_argument(
        '--web-only',
        action='store_true',
        help='تشغيل واجهة الويب فقط دون المراقبة'
    )
    
    args = parser.parse_args()
    
    # إنشاء محلل التهديدات
    global analyzer
    analyzer = APTWebAnalyzer(interface=args.interface, config_file=args.config)
    
    # عرض واجهات الشبكة
    if args.list_interfaces:
        print("📡 واجهات الشبكة المتاحة:")
        try:
            interfaces = scapy.get_if_list()
            for iface in interfaces:
                print(f"  - {iface}")
        except:
            print("  - eth0")
            print("  - wlan0")
        return
    
    # تدريب النموذج
    if args.train:
        print(f"🧠 تدريب النموذج باستخدام: {args.train}")
        if analyzer.train_model(args.train):
            print("✅ تم تدريب النموذج بنجاح")
        else:
            print("❌ فشل في تدريب النموذج")
        return
    
    # إنتاج تقرير
    if args.report:
        analyzer.generate_report()
        return
    
    # تشغيل واجهة الويب فقط
    if args.web_only:
        analyzer.start_web_gui()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            analyzer.stop_web_gui()
        return
    
    # بدء المراقبة
    print("🚀 بدء تشغيل محلل التهديدات المستمرة والمتطورة مع واجهة الويب")
    print("=" * 60)
    
    try:
        analyzer.start_capture()
    except KeyboardInterrupt:
        print("\n👋 تم إنهاء البرنامج بواسطة المستخدم")
    except Exception as e:
        print(f"❌ خطأ في تشغيل المحلل: {e}")
    finally:
        analyzer.generate_report()

def signal_handler(signum, frame):
    """معالج إشارة الإنهاء"""
    print("\n🛑 تم استلام إشارة الإنهاء...")
    analyzer.stop_capture()
    sys.exit(0)

if __name__ == "__main__":
    main()