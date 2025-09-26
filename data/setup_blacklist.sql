CREATE TABLE IF NOT EXISTS ip_blacklist(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip_address TEXT UNIQUE NOT NULL,
	failed_attempts INTEGER DEFAULT 0,
	first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	blacklisted BOOLEAN DEFAULT FALSE,
	blacklist_time TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_blacklist(ip_address);
CREATE INDEX IF NOT EXISTS idx_blacklist ON ip_blacklist(blacklisted);
EOF

sudo chown cowrie:cowrie /home/cowrie/cowrie/blacklist.db
