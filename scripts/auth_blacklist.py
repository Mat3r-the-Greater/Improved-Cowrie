# File: /home/cowrie/cowrie/src/cowrie/ssh/auth_blacklist.py

from cowrie.core.config import CowrieConfig
from cowrie.ssh.userauth import HoneyPotSSHUserAuthServer
from twisted.internet import reactor
import sys
import os

# Add the scripts directory to Python path
sys.path.append('/home/cowrie/cowrie/scripts')
from ip_blacklist import IPBlacklistManager

class BlacklistSSHUserAuthServer(HoneyPotSSHUserAuthServer):
    def __init__(self):
        super().__init__()
        self.blacklist_manager = IPBlacklistManager()
    
    def connectionMade(self):
        """Check blacklist when connection is made"""
        client_ip = self.transport.getPeer().host
        
        if self.blacklist_manager.is_blacklisted(client_ip):
            self.log.msg(f"Blocked connection from blacklisted IP: {client_ip}")
            # Drop connection immediately
            self.transport.loseConnection()
            return
        
        super().connectionMade()
    
    def auth_password(self, username, password):
        """Override password authentication to record failures"""
        client_ip = self.transport.getPeer().host
        
        # Check blacklist again before processing auth
        if self.blacklist_manager.is_blacklisted(client_ip):
            self.log.msg(f"Authentication blocked for blacklisted IP: {client_ip}")
            return False
        
        # Call original authentication
        result = super().auth_password(username, password)
        
        # If authentication failed, record the attempt
        if not result:
            was_blacklisted = self.blacklist_manager.record_failed_attempt(client_ip)
            if was_blacklisted:
                self.log.msg(f"IP {client_ip} has been blacklisted")
                # Drop connection after blacklisting
                reactor.callLater(1, self.transport.loseConnection)
        
        return result
