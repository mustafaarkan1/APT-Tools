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
    // يمكنك إضافة منطق لتحديث الواجهة هنا
});