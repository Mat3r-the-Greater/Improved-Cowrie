# File: /home/cowrie/scripts/ip_blacklist.py

import sqlite3
import threading
import time
from datetime import datetime, timedelta

class IPBlacklistManager:
    def __init__(self, db_path="/home/cowrie/cowrie/data/blacklist.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.max_attempts = 5 #max attempts allowed
        self.reset_window = 3600  # Reset attempt counter after 1 hour
        
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path, timeout=10.0)
    
    def is_blacklisted(self, ip_address):
        """Check if IP is blacklisted"""
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute(
                    "SELECT blacklisted FROM ip_blacklist WHERE ip_address = ? AND blacklisted = TRUE",
                    (ip_address,)
                )
                result = cursor.fetchone()
                conn.close()
                
                return result is not None
                
            except sqlite3.Error as e:
                print(f"Database error checking blacklist: {e}")
                return False
    
    def record_failed_attempt(self, ip_address):
        """Record a failed login attempt and blacklist if threshold reached"""
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                # Check if IP already exists
                cursor.execute(
                    "SELECT id, failed_attempts, first_attempt FROM ip_blacklist WHERE ip_address = ?",
                    (ip_address,)
                )
                result = cursor.fetchone()
                
                current_time = datetime.now()
                
                if result:
                    # IP exists, update attempt count
                    ip_id, failed_attempts, first_attempt = result
                    first_attempt_time = datetime.fromisoformat(first_attempt)
                    
                    # Reset counter if time window has passed
                    if current_time - first_attempt_time > timedelta(seconds=self.reset_window):
                        failed_attempts = 0
                        first_attempt_time = current_time
                    
                    new_attempts = failed_attempts + 1
                    
                    # Check if should be blacklisted
                    should_blacklist = new_attempts >= self.max_attempts
                    
                    cursor.execute("""
                        UPDATE ip_blacklist 
                        SET failed_attempts = ?, 
                            last_attempt = ?, 
                            first_attempt = ?,
                            blacklisted = ?,
                            blacklist_time = ?
                        WHERE id = ?
                    """, (
                        new_attempts, 
                        current_time.isoformat(),
                        first_attempt_time.isoformat(),
                        should_blacklist,
                        current_time.isoformat() if should_blacklist else None,
                        ip_id
                    ))
                    
                    if should_blacklist:
                        print(f"IP {ip_address} blacklisted after {new_attempts} failed attempts")
                        return True
                        
                else:
                    # New IP, create record
                    cursor.execute("""
                        INSERT INTO ip_blacklist (ip_address, failed_attempts, first_attempt, last_attempt)
                        VALUES (?, 1, ?, ?)
                    """, (ip_address, current_time.isoformat(), current_time.isoformat()))
                
                conn.commit()
                conn.close()
                return False
                
            except sqlite3.Error as e:
                print(f"Database error recording attempt: {e}")
                return False
    
    def get_blacklist_stats(self):
        """Get statistics about blacklisted IPs"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM ip_blacklist WHERE blacklisted = TRUE")
            blacklisted_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM ip_blacklist")
            total_ips = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT ip_address, failed_attempts, blacklist_time 
                FROM ip_blacklist 
                WHERE blacklisted = TRUE 
                ORDER BY blacklist_time DESC 
                LIMIT 10
            """)
            recent_blacklisted = cursor.fetchall()
            
            conn.close()
            
            return {
                'blacklisted_count': blacklisted_count,
                'total_ips': total_ips,
                'recent_blacklisted': recent_blacklisted
            }
            
        except sqlite3.Error as e:
            print(f"Database error getting stats: {e}")
            return None
    
    def remove_from_blacklist(self, ip_address):
        """Remove IP from blacklist (manual unban)"""
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE ip_blacklist 
                    SET blacklisted = FALSE, failed_attempts = 0
                    WHERE ip_address = ?
                """, (ip_address,))
                
                conn.commit()
                conn.close()
                
                print(f"Removed {ip_address} from blacklist")
                return True
                
            except sqlite3.Error as e:
                print(f"Database error removing from blacklist: {e}")
                return False
                
    def add_to_blacklist(self, ip_address, reason="Manual addition"):
        """Manually add IP to blacklist"""
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                current_time = datetime.now()
                
                # Check if IP already exists
                cursor.execute(
                    "SELECT id, blacklisted FROM ip_blacklist WHERE ip_address = ?",
                    (ip_address,)
                )
                result = cursor.fetchone()
                
                if result:
                    ip_id, is_blacklisted = result
                    if is_blacklisted:
                        print(f"IP {ip_address} is already blacklisted")
                        return False
                    else:
                        # Update existing record to blacklisted
                        cursor.execute("""
                            UPDATE ip_blacklist 
                            SET blacklisted = TRUE,
                                blacklist_time = ?,
                                failed_attempts = CASE 
                                    WHEN failed_attempts < ? THEN ?
                                    ELSE failed_attempts 
                                END,
                                last_attempt = ?
                            WHERE id = ?
                        """, (
                            current_time.isoformat(),
                            self.max_attempts,
                            self.max_attempts,
                            current_time.isoformat(),
                            ip_id
                        ))
                else:
                    # Create new blacklisted record
                    cursor.execute("""
                        INSERT INTO ip_blacklist 
                        (ip_address, failed_attempts, first_attempt, last_attempt, blacklisted, blacklist_time)
                        VALUES (?, ?, ?, ?, TRUE, ?)
                    """, (
                        ip_address, 
                        self.max_attempts,
                        current_time.isoformat(),
                        current_time.isoformat(),
                        current_time.isoformat()
                    ))
                
                conn.commit()
                conn.close()
                
                print(f"Manually blacklisted IP: {ip_address} - Reason: {reason}")
                return True
                
            except sqlite3.Error as e:
                print(f"Database error adding to blacklist: {e}")
                return False

    def add_multiple_ips(self, ip_list, reason="Bulk manual addition"):
        """Add multiple IPs to blacklist at once"""
        success_count = 0
        for ip in ip_list:
            if self.add_to_blacklist(ip.strip(), reason):
                success_count += 1
        
        print(f"Successfully added {success_count}/{len(ip_list)} IPs to blacklist")
        return success_count
