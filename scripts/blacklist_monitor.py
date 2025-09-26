# File: /home/cowrie/scripts/blacklist_monitor.py

#!/usr/bin/env python3
import sys
sys.path.append('/home/cowrie/cowrie/scripts')
from ip_blacklist import IPBlacklistManager
import argparse
import json

def main():
    parser = argparse.ArgumentParser(description='Manage IP Blacklist')
    parser.add_argument('--stats', action='store_true', help='Show blacklist statistics')
    parser.add_argument('--list', action='store_true', help='List all blacklisted IPs')
    parser.add_argument('--unban', type=str, help='Remove IP from blacklist')
    parser.add_argument('--check', type=str, help='Check if IP is blacklisted')
    parser.add_argument('--add', type=str, help='Manually add IP to blacklist')
    parser.add_argument('--reason', type=str, default='Manual addition', help='Reason for manual blacklist')
    
    args = parser.parse_args()
    manager = IPBlacklistManager()
    
    if args.stats:
        stats = manager.get_blacklist_stats()
        if stats:
            print(f"Total IPs tracked: {stats['total_ips']}")
            print(f"Blacklisted IPs: {stats['blacklisted_count']}")
            print("\nRecent blacklisted IPs:")
            for ip, attempts, blacklist_time in stats['recent_blacklisted']:
                print(f"  {ip}: {attempts} attempts, blacklisted at {blacklist_time}")
    
    elif args.check:
        is_blacklisted = manager.is_blacklisted(args.check)
        print(f"IP {args.check} is {'blacklisted' if is_blacklisted else 'not blacklisted'}")
    
    elif args.unban:
        success = manager.remove_from_blacklist(args.unban)
        if success:
            print(f"Successfully removed {args.unban} from blacklist")
        else:
            print(f"Failed to remove {args.unban} from blacklist")
    
    elif args.list:
        # Implementation for listing all blacklisted IPs
        pass
        
    elif args.add:
        success = manager.add_to_blacklist(args.add, args.reason)
        if success:
            print(f"Successfully added {args.add} to blacklist")
        else:
            print(f"Failed to add {args.add} to blacklist (may already exist)")

if __name__ == "__main__":
    main()
