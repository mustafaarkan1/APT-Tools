// تهيئة اتصال Socket.IO
const socket = io();

// العناصر الرئيسية في الصفحة
const elements = {
    totalPackets: document.getElementById('total-packets'),
    totalThreats: document.getElementById('total-threats'),
    threatLevel: document.getElementById('threat-level'),
    captureStatus: document.getElementById('capture-status'),
    captureStatusIcon: document.getElementById('capture-status-icon'),
    interfaceStatus: document.getElementById('interface-status'),
    uptime: document.getElementById('uptime'),
    alertsBody: document.getElementById('alerts-tbody'),
    threatsBody: document.getElementById('threats-tbody'),
    startButton: document.getElementById('start-capture'),
    stopButton: document.getElementById('stop-capture'),
    interfaceSelect: document.getElementById('interface-select'),
    settingsForm: document.getElementById('settings-form')
};

// إعداد الرسوم البيانية
const charts = {
    protocols: new Chart(document.getElementById('protocols-chart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#2563eb',
                    '#16a34a',
                    '#ca8a04',
                    '#dc2626',
                    '#8b5cf6'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    }),

    networkActivity: new Chart(document.getElementById('network-activity-chart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'نشاط الشبكة',
                data: [],
                borderColor: '#2563eb',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    })
};

// متغيرات عامة
let isCapturing = false;
let startTime = null;
let uptimeInterval = null;

// دوال المساعدة
const helpers = {
    formatNumber: (num) => {
        return new Intl.NumberFormat('ar-SA').format(num);
    },

    formatTime: (seconds) => {
        const hrs = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return `${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    },

    getSeverityClass: (severity) => {
        const classes = {
            'عالي': 'danger',
            'متوسط': 'warning',
            'منخفض': 'success'
        };
        return classes[severity] || 'primary';
    },

    updateUptime: () => {
        if (startTime) {
            const seconds = Math.floor((Date.now() - startTime) / 1000);
            elements.uptime.textContent = helpers.formatTime(seconds);
        }
    }
};

// معالجة الأحداث
const handlers = {
    startCapture: async () => {
        try {
            const response = await fetch('/start_capture', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    interface: elements.interfaceSelect.value
                })
            });

            const data = await response.json();
            if (data.status === 'success') {
                isCapturing = true;
                startTime = Date.now();
                elements.startButton.disabled = true;
                elements.stopButton.disabled = false;
                elements.captureStatus.textContent = 'جاري المراقبة';
                elements.captureStatusIcon.style.color = '#16a34a';
                
                // بدء مؤقت وقت التشغيل
                uptimeInterval = setInterval(helpers.updateUptime, 1000);
            }
        } catch (error) {
            console.error('خطأ في بدء المراقبة:', error);
            alert('حدث خطأ في بدء المراقبة');
        }
    },

    stopCapture: async () => {
        try {
            const response = await fetch('/stop_capture');
            const data = await response.json();
            if (data.status === 'success') {
                isCapturing = false;
                elements.startButton.disabled = false;
                elements.stopButton.disabled = true;
                elements.captureStatus.textContent = 'متوقف';
                elements.captureStatusIcon.style.color = '#dc2626';
                
                // إيقاف مؤقت وقت التشغيل
                clearInterval(uptimeInterval);
            }
        } catch (error) {
            console.error('خطأ في إيقاف المراقبة:', error);
            alert('حدث خطأ في إيقاف المراقبة');
        }
    },

    updateStats: (stats) => {
        elements.totalPackets.textContent = helpers.formatNumber(stats.total_packets);
        elements.totalThreats.textContent = helpers.formatNumber(stats.suspicious_activities);
        elements.threatLevel.textContent = stats.threat_level;
        
        // تحديث الرسم البياني للبروتوكولات
        charts.protocols.data.labels = Object.keys(stats.protocols);
        charts.protocols.data.datasets[0].data = Object.values(stats.protocols);
        charts.protocols.update();
        
        // تحديث رسم النشاط
        const time = new Date().toLocaleTimeString('ar-SA');
        charts.networkActivity.data.labels.push(time);
        charts.networkActivity.data.datasets[0].data.push(stats.total_packets);
        
        // الاحتفاظ بآخر 10 نقاط
        if (charts.networkActivity.data.labels.length > 10) {
            charts.networkActivity.data.labels.shift();
            charts.networkActivity.data.datasets[0].data.shift();
        }
        charts.networkActivity.update();
    },

    addAlert: (alert) => {
        const row = document.createElement('tr');
        const severityClass = helpers.getSeverityClass(alert.severity);
        
        row.innerHTML = `
            <td>${new Date(alert.timestamp).toLocaleString('ar-SA')}</td>
            <td>${alert.type}</td>
            <td>${alert.src_ip || '-'}</td>
            <td><span class="badge ${severityClass}">${alert.severity}</span></td>
            <td>${alert.description}</td>
        `;
        
        elements.alertsBody.insertBefore(row, elements.alertsBody.firstChild);
        
        // الاحتفاظ بآخر 10 تنبيهات
        if (elements.alertsBody.children.length > 10) {
            elements.alertsBody.removeChild(elements.alertsBody.lastChild);
        }
    },

    updateThreatChains: (chains) => {
        elements.threatsBody.innerHTML = '';
        
        Object.entries(chains).forEach(([ip, chain]) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${ip}</td>
                <td>
                    <div class="risk-meter" style="--risk: ${chain.risk_score}%">
                        ${chain.risk_score}
                    </div>
                </td>
                <td>${chain.activities.length}</td>
                <td>${new Date(chain.last_seen).toLocaleString('ar-SA')}</td>
                <td>
                    <button class="btn-primary btn-sm" onclick="showThreatDetails('${ip}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn-danger btn-sm" onclick="blockIP('${ip}')">
                        <i class="fas fa-ban"></i>
                    </button>
                </td>
            `;
            elements.threatsBody.appendChild(row);
        });
    }
};

// استماع لأحداث Socket.IO
socket.on('connect', () => {
    console.log('تم الاتصال بالخادم');
});

socket.on('status_update', (data) => {
    isCapturing = data.status;
    elements.interfaceStatus.textContent = data.interface;
    
    if (isCapturing) {
        elements.startButton.disabled = true;
        elements.stopButton.disabled = false;
        elements.captureStatus.textContent = 'جاري المراقبة';
        elements.captureStatusIcon.style.color = '#16a34a';
    } else {
        elements.startButton.disabled = false;
        elements.stopButton.disabled = true;
        elements.captureStatus.textContent = 'متوقف';
        elements.captureStatusIcon.style.color = '#dc2626';
    }
});

socket.on('stats_update', handlers.updateStats);
socket.on('new_alert', handlers.addAlert);
socket.on('threat_chains_update', handlers.updateThreatChains);

// إعداد مستمعي الأحداث
elements.startButton.addEventListener('click', handlers.startCapture);
elements.stopButton.addEventListener('click', handlers.stopCapture);

elements.settingsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
        const response = await fetch('/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(Object.fromEntries(formData))
        });
        
        if (response.ok) {
            alert('تم حفظ الإعدادات بنجاح');
        } else {
            throw new Error('فشل في حفظ الإعدادات');
        }
    } catch (error) {
        console.error('خطأ في حفظ الإعدادات:', error);
        alert('حدث خطأ في حفظ الإعدادات');
    }
});

// تحميل واجهات الشبكة المتاحة
fetch('/interfaces')
    .then(response => response.json())
    .then(interfaces => {
        interfaces.forEach(iface => {
            const option = document.createElement('option');
            option.value = iface;
            option.textContent = iface;
            elements.interfaceSelect.appendChild(option);
        });
    })
    .catch(console.error);

// دوال مساعدة إضافية للواجهة
// تكملة الملف السابق...

window.showThreatDetails = (ip) => {
    const modal = document.getElementById('threat-modal');
    const details = document.getElementById('threat-details');
    const timeline = document.getElementById('threat-timeline');
    
    // جلب تفاصيل التهديد
    fetch(`/threat_chains/${ip}`)
        .then(response => response.json())
        .then(chain => {
            details.innerHTML = `
                <div class="threat-info">
                    <div class="info-group">
                        <label>عنوان IP:</label>
                        <span>${ip}</span>
                    </div>
                    <div class="info-group">
                        <label>أول ظهور:</label>
                        <span>${new Date(chain.first_seen).toLocaleString('ar-SA')}</span>
                    </div>
                    <div class="info-group">
                        <label>آخر نشاط:</label>
                        <span>${new Date(chain.last_seen).toLocaleString('ar-SA')}</span>
                    </div>
                    <div class="info-group">
                        <label>درجة الخطورة:</label>
                        <span class="risk-score">${chain.risk_score}</span>
                    </div>
                </div>
            `;

            // إنشاء الجدول الزمني للأنشطة
            timeline.innerHTML = chain.activities.map(activity => `
                <div class="timeline-item ${helpers.getSeverityClass(activity.severity)}">
                    <div class="timeline-time">
                        ${new Date(activity.timestamp).toLocaleTimeString('ar-SA')}
                    </div>
                    <div class="timeline-content">
                        <h4>${activity.type}</h4>
                        <p>${activity.description}</p>
                    </div>
                </div>
            `).join('');

            modal.style.display = 'block';
        })
        .catch(error => {
            console.error('خطأ في جلب تفاصيل التهديد:', error);
            alert('حدث خطأ في جلب تفاصيل التهديد');
        });
};

window.blockIP = async (ip) => {
    if (confirm(`هل أنت متأكد من حظر ${ip}?`)) {
        try {
            const response = await fetch('/block_ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip })
            });
            
            const result = await response.json();
            if (result.success) {
                alert(`تم حظر ${ip} بنجاح`);
            } else {
                throw new Error(result.message);
            }
        } catch (error) {
            console.error('خطأ في حظر IP:', error);
            alert('حدث خطأ في عملية الحظر');
        }
    }
};

// إغلاق النوافذ المنبثقة
document.querySelectorAll('.modal .close').forEach(closeBtn => {
    closeBtn.addEventListener('click', () => {
        closeBtn.closest('.modal').style.display = 'none';
    });
});

// إغلاق النوافذ المنبثقة عند النقر خارجها
window.addEventListener('click', (e) => {
    document.querySelectorAll('.modal').forEach(modal => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });
});

// تحديث حالة إعدادات البريد الإلكتروني
document.querySelector('input[name="email_alerts"]').addEventListener('change', (e) => {
    const emailSettings = document.getElementById('email-settings');
    emailSettings.style.display = e.target.checked ? 'block' : 'none';
});

// تحديث قيمة الحساسية
const sensitivityInput = document.getElementById('sensitivity');
const sensitivityValue = document.getElementById('sensitivity-value');
sensitivityInput.addEventListener('input', (e) => {
    sensitivityValue.textContent = `${e.target.value}%`;
});

// إعادة ضبط الإعدادات
document.getElementById('reset-settings').addEventListener('click', () => {
    if (confirm('هل أنت متأكد من إعادة ضبط جميع الإعدادات؟')) {
        elements.settingsForm.reset();
        sensitivityValue.textContent = '50%';
        document.getElementById('email-settings').style.display = 'none';
    }
});

// تصدير التفاصيل
document.getElementById('export-details').addEventListener('click', async () => {
    try {
        const response = await fetch('/export_report');
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `apt_report_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('خطأ في تصدير التقرير:', error);
        alert('حدث خطأ في تصدير التقرير');
    }
});

// تحديث الرسوم البيانية بشكل دوري
setInterval(() => {
    if (isCapturing) {
        fetch('/network_stats')
            .then(response => response.json())
            .then(handlers.updateStats)
            .catch(console.error);
    }
}, 5000);

// تهيئة tooltips
const tooltips = document.querySelectorAll('[data-tooltip]');
tooltips.forEach(tooltip => {
    tooltip.addEventListener('mouseover', (e) => {
        const tip = document.createElement('div');
        tip.className = 'tooltip';
        tip.textContent = e.target.dataset.tooltip;
        document.body.appendChild(tip);
        
        const rect = e.target.getBoundingClientRect();
        tip.style.top = `${rect.top - tip.offsetHeight - 10}px`;
        tip.style.left = `${rect.left + (rect.width - tip.offsetWidth) / 2}px`;
        
        e.target.addEventListener('mouseleave', () => tip.remove());
    });
});

// معالجة أحداث النظام المظلم/الفاتح
const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
const updateTheme = (e) => {
    document.body.classList.toggle('dark-mode', e.matches);
    // تحديث ألوان الرسوم البيانية
    const chartColors = e.matches ? {
        backgroundColor: '#1e293b',
        borderColor: '#ffffff',
        textColor: '#ffffff'
    } : {
        backgroundColor: '#ffffff',
        borderColor: '#1e293b',
        textColor: '#1e293b'
    };
    
    // تحديث إعدادات الرسوم البيانية
    Object.values(charts).forEach(chart => {
        chart.options.plugins.legend.labels.color = chartColors.textColor;
        chart.options.scales.y.grid.color = chartColors.borderColor;
        chart.options.scales.x.grid.color = chartColors.borderColor;
        chart.update();
    });
};

darkModeMediaQuery.addListener(updateTheme);
updateTheme(darkModeMediaQuery);

// تهيئة تحميل الصفحة
document.addEventListener('DOMContentLoaded', () => {
    // تحديث حالة المراقبة
    fetch('/capture_status')
        .then(response => response.json())
        .then(status => {
            isCapturing = status.is_capturing;
            if (isCapturing) {
                startTime = new Date(status.start_time);
                uptimeInterval = setInterval(helpers.updateUptime, 1000);
                elements.startButton.disabled = true;
                elements.stopButton.disabled = false;
                elements.captureStatus.textContent = 'جاري المراقبة';
                elements.captureStatusIcon.style.color = '#16a34a';
            }
        })
        .catch(console.error);
    
    // تحميل الإعدادات الحالية
    fetch('/config')
        .then(response => response.json())
        .then(config => {
            // تعبئة نموذج الإعدادات
            Object.entries(config).forEach(([key, value]) => {
                const input = elements.settingsForm.elements[key];
                if (input) {
                    if (input.type === 'checkbox') {
                        input.checked = value;
                    } else {
                        input.value = value;
                    }
                }
            });
            
            // تحديث حالة إعدادات البريد
            const emailSettings = document.getElementById('email-settings');
            emailSettings.style.display = config.email_alerts ? 'block' : 'none';
        })
        .catch(console.error);
});