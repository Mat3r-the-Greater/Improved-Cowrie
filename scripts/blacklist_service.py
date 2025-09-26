# File: /home/cowrie/scripts/blacklist_service.py

#!/usr/bin/env python3
import json
import time
import sys
sys.path.append('/home/cowrie/cowrie/scripts')
from ip_blacklist import IPBlacklistManager

class BlacklistLogMonitor:
    def __init__(self):
        self.log_file = "/home/jd/cowrie/cowrie/log/cowrie.json"
        self.manager = IPBlacklistManager()
    
    def monitor_logs(self):
        """Monitor Cowrie logs for failed login attempts"""
        try:
            with open(self.log_file, 'r') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        try:
                            entry = json.loads(line.strip())
                            if entry.get('eventid') == 'cowrie.login.failed':
                                ip = entry.get('src_ip')
                                if ip:
                                    self.manager.record_failed_attempt(ip)
                        except json.JSONDecodeError:
                            continue
                    else:
                        time.sleep(1)
                        
        except FileNotFoundError:
            print(f"Log file not found: {self.log_file}")
            time.sleep(5)
            self.monitor_logs()  # Retry

if __name__ == "__main__":
    monitor = BlacklistLogMonitor()
    monitor.monitor_logs()
