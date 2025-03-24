import os
import sys
import re
import shlex
import subprocess
import sqlite3
import ctypes
from flask import Flask, request, jsonify
from threading import Thread
import win32serviceutil
import win32service
import win32event
import time
from datetime import datetime, timedelta
from flask_httpauth import HTTPBasicAuth


app = Flask(__name__)
auth = HTTPBasicAuth()
USER_CREDENTIALS = {
    "admin": "Pb121212!!!"
}
SERVICE_NAME = "ip_add_auto"
SERVICE_DISPLAY_NAME = "IP Auto Firewall Service"
DB_FILE = "waf_protect.db"
RATE_LIMIT = 5  # 每个IP每60秒最多请求5次
RATE_LIMIT_WINDOW = 60  # 时间窗口（秒）

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS access_log (
            ip TEXT PRIMARY KEY,
            last_access_time TEXT,
            request_count INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def update_access_log(ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    now = datetime.now()

    # 查询这个IP的历史访问记录
    c.execute('SELECT last_access_time, request_count FROM access_log WHERE ip = ?', (ip,))
    record = c.fetchone()

    if record:
        last_time = datetime.fromisoformat(record[0])
        count = record[1]

        # 计算当前时间和上次访问时间差
        if (now - last_time).total_seconds() <= RATE_LIMIT_WINDOW:
            count += 1
        else:
            count = 1  # 超过时间窗口，重新计数
        c.execute('UPDATE access_log SET last_access_time=?, request_count=? WHERE ip=?',
                  (now.isoformat(), count, ip))
    else:
        c.execute('INSERT INTO access_log (ip, last_access_time, request_count) VALUES (?, ?, ?)',
                  (ip, now.isoformat(), 1))

    conn.commit()
    conn.close()

def is_rate_limited(ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    now = datetime.now()

    c.execute('SELECT last_access_time, request_count FROM access_log WHERE ip = ?', (ip,))
    record = c.fetchone()

    conn.close()

    if record:
        last_time = datetime.fromisoformat(record[0])
        count = record[1]
        if (now - last_time).total_seconds() <= RATE_LIMIT_WINDOW and count >= RATE_LIMIT:
            return True

    return False


@auth.verify_password
def verify_password(username, password):
    if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
        return username
    return None
    
@app.before_request
def check_rate_limit():
    ip = get_request_ip()
    if is_rate_limited(ip):
        return jsonify({"status": "error", "message": "Too many requests"}), 429
    update_access_log(ip)

def is_valid_ipv4(ip):
    pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$')
    return pattern.match(ip) is not None

def escape_ip(ip):
    return shlex.quote(ip)

def get_request_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

@app.route('/add_fff', methods=['GET', 'POST'])
@auth.login_required
def add_fff():
    ip = get_request_ip()
    if not is_valid_ipv4(ip):
        return jsonify({"status": "error", "message": f"Invalid IP: {ip}"}), 400

    safe_ip = escape_ip(ip)
    rule_name = f"Allow_RDP_{safe_ip}"

    cmd = f'netsh advfirewall firewall add rule name={shlex.quote(rule_name)} dir=in action=allow protocol=TCP localport=443 remoteip={safe_ip}'
    try:
        subprocess.run(cmd, shell=True, check=True)
        return jsonify({"status": "success", "message": f"IP {ip} added to RDP whitelist"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/remove_fff', methods=['GET', 'POST'])
def remove_fff():
    ip = get_request_ip()
    if not is_valid_ipv4(ip):
        return jsonify({"status": "error", "message": f"Invalid IP: {ip}"}), 400

    safe_ip = escape_ip(ip)
    rule_name = f"Allow_RDP_{safe_ip}"

    cmd = f'netsh advfirewall firewall delete rule name={shlex.quote(rule_name)}'
    try:
        subprocess.run(cmd, shell=True, check=True)
        return jsonify({"status": "success", "message": f"IP {ip} removed from RDP whitelist"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500

class FirewallService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.server_thread = Thread(target=self.run_flask_server)

    def run_flask_server(self):
        init_db()
        app.run(host='0.0.0.0', port=8080, threaded=True)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        add_firewall_rule()
        self.server_thread.start()
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

def add_firewall_rule():
    cmd = 'netsh advfirewall firewall add rule name="FlaskService8080" dir=in action=allow protocol=TCP localport=8080'
    try:
        subprocess.run(cmd, shell=True, check=True)
        print("Flask服务端口8080已加入防火墙白名单")
    except subprocess.CalledProcessError as e:
        print(f"添加防火墙规则失败: {e}")

if __name__ == '__main__':
    if len(sys.argv) == 1:
        import servicemanager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(FirewallService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(FirewallService)
