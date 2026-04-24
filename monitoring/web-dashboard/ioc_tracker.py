#!/usr/bin/env python3
"""
IOC Tracker - Indicators of Compromise tracking and management system
Tracks attackers, their behavior, and maintains threat intelligence
"""

import json
import os
import sqlite3
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import threading

# Configuration
IOC_DB_PATH = Path(os.getenv('IOC_DB_PATH', '/iocs/ioc_database.db'))
IOC_RETENTION_DAYS = int(os.getenv('IOC_RETENTION_DAYS', '90'))
SUSPICIOUS_THRESHOLD = int(os.getenv('SUSPICIOUS_THRESHOLD', '10'))
BLOCK_THRESHOLD = int(os.getenv('BLOCK_THRESHOLD', '50'))
AUTO_BLOCK_ENABLED = os.getenv('AUTO_BLOCK_ENABLED', 'false').lower() == 'true'

# Ensure directory exists
try:
    IOC_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
except OSError:
    pass


@dataclass
class IOCRecord:
    """Represents a single IOC record"""
    id: Optional[int] = None
    ip_address: str = ""
    attack_type: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    attempt_count: int = 0
    blocked: bool = False
    suspicious: bool = False
    country_code: Optional[str] = None
    user_agent: Optional[str] = None
    notes: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'IOCRecord':
        return cls(**data)


class IOCDatabase:
    """SQLite database for IOC storage"""
    
    def __init__(self, db_path: Path = IOC_DB_PATH):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(str(self.db_path))
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection
    
    def _init_db(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    attempt_count INTEGER DEFAULT 1,
                    blocked BOOLEAN DEFAULT 0,
                    suspicious BOOLEAN DEFAULT 0,
                    country_code TEXT,
                    user_agent TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, attack_type)
                )
            ''')
            
            # Create indexes for faster queries
            conn.execute('CREATE INDEX IF NOT EXISTS idx_ip ON iocs(ip_address)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_attack_type ON iocs(attack_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_blocked ON iocs(blocked)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_last_seen ON iocs(last_seen)')
            
            # Create table for detailed attack logs
            conn.execute('''
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    request_method TEXT,
                    endpoint TEXT,
                    payload TEXT,
                    headers TEXT,
                    response_code INTEGER,
                    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                )
            ''')
            
            conn.execute('CREATE INDEX IF NOT EXISTS idx_ioc_id ON attack_logs(ioc_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON attack_logs(timestamp)')
            
            conn.commit()
    
    def record_attack(self, ip_address: str, attack_type: str, 
                     details: Optional[Dict] = None) -> IOCRecord:
        """Record or update an IOC entry"""
        details = details or {}
        now = datetime.utcnow().isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.execute(
                'SELECT * FROM iocs WHERE ip_address = ? AND attack_type = ?',
                (ip_address, attack_type)
            )
            row = cursor.fetchone()
            
            if row:
                # Update existing record
                attempt_count = row['attempt_count'] + 1
                suspicious = attempt_count >= SUSPICIOUS_THRESHOLD
                blocked = row['blocked'] or (AUTO_BLOCK_ENABLED and attempt_count >= BLOCK_THRESHOLD)
                
                conn.execute('''
                    UPDATE iocs 
                    SET attempt_count = ?, 
                        last_seen = ?,
                        suspicious = ?,
                        blocked = ?,
                        updated_at = ?
                    WHERE id = ?
                ''', (attempt_count, now, suspicious, blocked, now, row['id']))
                
                ioc_id = row['id']
                
            else:
                # Create new record
                suspicious = 1 >= SUSPICIOUS_THRESHOLD
                blocked = AUTO_BLOCK_ENABLED and 1 >= BLOCK_THRESHOLD
                
                cursor = conn.execute('''
                    INSERT INTO iocs 
                    (ip_address, attack_type, first_seen, last_seen, attempt_count, 
                     suspicious, blocked, country_code, user_agent, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ip_address, attack_type, now, now, 1,
                    suspicious, blocked,
                    details.get('country_code'),
                    details.get('user_agent'),
                    details.get('notes'),
                    now, now
                ))
                
                ioc_id = cursor.lastrowid
            
            # Log attack details
            if details:
                conn.execute('''
                    INSERT INTO attack_logs 
                    (ioc_id, timestamp, request_method, endpoint, payload, headers, response_code)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc_id,
                    now,
                    details.get('request_method'),
                    details.get('endpoint'),
                    json.dumps(details.get('payload')),
                    json.dumps(details.get('headers')),
                    details.get('response_code')
                ))
            
            conn.commit()
            
            # Return updated record
            return self.get_ioc_by_id(ioc_id)
    
    def get_ioc_by_id(self, ioc_id: int) -> Optional[IOCRecord]:
        """Get IOC by ID"""
        with self._get_connection() as conn:
            cursor = conn.execute('SELECT * FROM iocs WHERE id = ?', (ioc_id,))
            row = cursor.fetchone()
            
            if row:
                return IOCRecord(**dict(row))
            return None
    
    def get_ioc_by_ip(self, ip_address: str) -> List[IOCRecord]:
        """Get all IOCs for an IP address"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                'SELECT * FROM iocs WHERE ip_address = ? ORDER BY last_seen DESC',
                (ip_address,)
            )
            return [IOCRecord(**dict(row)) for row in cursor.fetchall()]
    
    def get_all_iocs(self, blocked_only: bool = False, 
                     suspicious_only: bool = False,
                     attack_type: Optional[str] = None) -> List[IOCRecord]:
        """Get all IOCs with optional filtering"""
        query = 'SELECT * FROM iocs WHERE 1=1'
        params = []
        
        if blocked_only:
            query += ' AND blocked = 1'
        if suspicious_only:
            query += ' AND suspicious = 1'
        if attack_type:
            query += ' AND attack_type = ?'
            params.append(attack_type)
        
        query += ' ORDER BY last_seen DESC'
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [IOCRecord(**dict(row)) for row in cursor.fetchall()]
    
    def block_ip(self, ip_address: str, reason: str = "Manual block") -> bool:
        """Block an IP address"""
        now = datetime.utcnow().isoformat()
        
        with self._get_connection() as conn:
            conn.execute('''
                UPDATE iocs 
                SET blocked = 1, notes = ?, updated_at = ?
                WHERE ip_address = ?
            ''', (reason, now, ip_address))
            conn.commit()
            return conn.total_changes > 0
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        now = datetime.utcnow().isoformat()
        
        with self._get_connection() as conn:
            conn.execute('''
                UPDATE iocs 
                SET blocked = 0, notes = ?, updated_at = ?
                WHERE ip_address = ?
            ''', ('Unblocked', now, ip_address))
            conn.commit()
            return conn.total_changes > 0
    
    def is_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                'SELECT 1 FROM iocs WHERE ip_address = ? AND blocked = 1 LIMIT 1',
                (ip_address,)
            )
            return cursor.fetchone() is not None
    
    def get_attack_stats(self) -> Dict:
        """Get aggregate attack statistics"""
        with self._get_connection() as conn:
            stats = {}
            
            # Total IOCs
            cursor = conn.execute('SELECT COUNT(*) as count FROM iocs')
            stats['total_iocs'] = cursor.fetchone()['count']
            
            # Blocked IPs
            cursor = conn.execute('SELECT COUNT(DISTINCT ip_address) as count FROM iocs WHERE blocked = 1')
            stats['blocked_ips'] = cursor.fetchone()['count']
            
            # Suspicious IPs
            cursor = conn.execute('SELECT COUNT(DISTINCT ip_address) as count FROM iocs WHERE suspicious = 1')
            stats['suspicious_ips'] = cursor.fetchone()['count']
            
            # Attack types breakdown
            cursor = conn.execute('''
                SELECT attack_type, COUNT(*) as count, SUM(attempt_count) as total_attempts
                FROM iocs
                GROUP BY attack_type
                ORDER BY count DESC
            ''')
            stats['attack_types'] = [dict(row) for row in cursor.fetchall()]
            
            # Recent activity (last 24 hours)
            yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
            cursor = conn.execute('''
                SELECT COUNT(*) as count FROM iocs WHERE last_seen > ?
            ''', (yesterday,))
            stats['recent_iocs'] = cursor.fetchone()['count']
            
            # Top attackers
            cursor = conn.execute('''
                SELECT ip_address, SUM(attempt_count) as total_attempts, 
                       COUNT(DISTINCT attack_type) as attack_types
                FROM iocs
                GROUP BY ip_address
                ORDER BY total_attempts DESC
                LIMIT 10
            ''')
            stats['top_attackers'] = [dict(row) for row in cursor.fetchall()]
            
            return stats
    
    def cleanup_old_iocs(self, retention_days: int = IOC_RETENTION_DAYS) -> int:
        """Delete IOCs older than retention period"""
        cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
        
        with self._get_connection() as conn:
            # First, delete old attack logs
            conn.execute('''
                DELETE FROM attack_logs 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            
            # Then delete old IOCs (but keep blocked ones)
            conn.execute('''
                DELETE FROM iocs 
                WHERE last_seen < ? AND blocked = 0
            ''', (cutoff_date,))
            
            deleted_count = conn.total_changes
            conn.commit()
            
            return deleted_count
    
    def get_attack_logs(self, ip_address: Optional[str] = None,
                       start_time: Optional[str] = None,
                       end_time: Optional[str] = None,
                       limit: int = 100) -> List[Dict]:
        """Get detailed attack logs with filtering"""
        query = '''
            SELECT al.*, i.ip_address, i.attack_type
            FROM attack_logs al
            JOIN iocs i ON al.ioc_id = i.id
            WHERE 1=1
        '''
        params = []
        
        if ip_address:
            query += ' AND i.ip_address = ?'
            params.append(ip_address)
        if start_time:
            query += ' AND al.timestamp >= ?'
            params.append(start_time)
        if end_time:
            query += ' AND al.timestamp <= ?'
            params.append(end_time)
        
        query += ' ORDER BY al.timestamp DESC LIMIT ?'
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]


# Global IOC database instance
_ioc_db = None
_ioc_lock = threading.Lock()


def get_ioc_db() -> IOCDatabase:
    """Get or create IOC database singleton"""
    global _ioc_db
    if _ioc_db is None:
        with _ioc_lock:
            if _ioc_db is None:
                _ioc_db = IOCDatabase()
    return _ioc_db


class IPBlocker:
    """Manages IP blocking with multiple backend support"""
    
    def __init__(self, ioc_db: Optional[IOCDatabase] = None):
        self.ioc_db = ioc_db or get_ioc_db()
        self.blocked_ips: set = set()
        self._load_blocked_ips()
    
    def _load_blocked_ips(self):
        """Load blocked IPs from database into memory"""
        iocs = self.ioc_db.get_all_iocs(blocked_only=True)
        self.blocked_ips = {ioc.ip_address for ioc in iocs}
    
    def is_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked (memory + DB)"""
        if ip_address in self.blocked_ips:
            return True
        
        # Double-check with DB
        if self.ioc_db.is_blocked(ip_address):
            self.blocked_ips.add(ip_address)
            return True
        
        return False
    
    def block(self, ip_address: str, reason: str = "Attack detected") -> bool:
        """Block an IP address"""
        success = self.ioc_db.block_ip(ip_address, reason)
        if success:
            self.blocked_ips.add(ip_address)
        return success
    
    def unblock(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        success = self.ioc_db.unblock_ip(ip_address)
        if success:
            self.blocked_ips.discard(ip_address)
        return success
    
    def check_and_block(self, ip_address: str, attempt_count: int) -> bool:
        """Check if IP should be auto-blocked based on threshold"""
        if AUTO_BLOCK_ENABLED and attempt_count >= BLOCK_THRESHOLD:
            return self.block(ip_address, f"Auto-blocked after {attempt_count} attempts")
        return False


# Convenience functions
def record_ioc(ip_address: str, attack_type: str, details: Optional[Dict] = None) -> IOCRecord:
    """Quick function to record an IOC"""
    db = get_ioc_db()
    return db.record_attack(ip_address, attack_type, details)


def is_ip_blocked(ip_address: str) -> bool:
    """Quick check if IP is blocked"""
    db = get_ioc_db()
    return db.is_blocked(ip_address)


def get_ioc_stats() -> Dict:
    """Get IOC statistics"""
    db = get_ioc_db()
    return db.get_attack_stats()


# Example usage
if __name__ == '__main__':
    print("Testing IOC Tracker...")
    
    # Test database
    db = get_ioc_db()
    
    # Record some test IOCs
    test_ips = ['192.168.1.100', '10.0.0.50', '192.168.1.100']
    
    for ip in test_ips:
        ioc = db.record_attack(ip, 'sql_injection', {
            'country_code': 'US',
            'user_agent': 'Mozilla/5.0',
            'request_method': 'POST',
            'endpoint': '/login',
            'payload': "' OR 1=1 --",
            'response_code': 403
        })
        print(f"Recorded IOC: {ioc.ip_address} - Attempts: {ioc.attempt_count}")
    
    # Get stats
    stats = db.get_attack_stats()
    print(f"\nStatistics:")
    print(f"  Total IOCs: {stats['total_iocs']}")
    print(f"  Blocked IPs: {stats['blocked_ips']}")
    print(f"  Attack Types: {len(stats['attack_types'])}")
    
    # Test blocking
    blocker = IPBlocker(db)
    blocker.block('10.0.0.99', 'Test block')
    print(f"\nIs 10.0.0.99 blocked? {blocker.is_blocked('10.0.0.99')}")
    
    print("\nIOC Tracker test complete!")
