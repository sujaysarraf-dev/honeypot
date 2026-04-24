#!/usr/bin/env python3
"""
Retention Manager - Automated log and IOC cleanup system
Handles log rotation, archival, and deletion based on retention policies
"""

import os
import json
import gzip
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass
import threading
import time
import schedule

# Configuration from environment
LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', '30'))
IOC_RETENTION_DAYS = int(os.getenv('IOC_RETENTION_DAYS', '90'))
ARCHIVE_RETENTION_DAYS = int(os.getenv('ARCHIVE_RETENTION_DAYS', '365'))
LOG_DIR = Path(os.getenv('LOG_DIR', '/logs'))
DATA_DIR = Path(os.getenv('DATA_DIR', '/data'))
ARCHIVE_DIR = Path(os.getenv('ARCHIVE_DIR', '/data/archives'))
CLEANUP_SCHEDULE = os.getenv('CLEANUP_SCHEDULE', '02:00')  # 2 AM daily
ENABLE_AUTO_CLEANUP = os.getenv('ENABLE_AUTO_CLEANUP', 'true').lower() == 'true'

# Ensure directories exist
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

# Setup logger
logger = logging.getLogger(__name__)


@dataclass
class CleanupResult:
    """Result of a cleanup operation"""
    operation: str
    files_processed: int
    files_deleted: int
    files_archived: int
    bytes_freed: int
    errors: List[str]
    timestamp: str
    
    def to_dict(self) -> Dict:
        return {
            'operation': self.operation,
            'files_processed': self.files_processed,
            'files_deleted': self.files_deleted,
            'files_archived': self.files_archived,
            'bytes_freed': self.bytes_freed,
            'errors': self.errors,
            'timestamp': self.timestamp
        }


class LogRetentionManager:
    """Manages log file retention and cleanup"""
    
    def __init__(self, log_dir: Path = LOG_DIR, archive_dir: Path = ARCHIVE_DIR):
        self.log_dir = log_dir
        self.archive_dir = archive_dir
        self.archive_dir.mkdir(parents=True, exist_ok=True)
    
    def rotate_log_file(self, log_file: Path) -> Optional[Path]:
        """
        Rotate a single log file (compress and archive)
        
        Process:
        1. Close current log file
        2. Rename with timestamp
        3. Compress with gzip
        4. Move to archive directory
        """
        if not log_file.exists():
            return None
        
        # Generate archive filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        archive_name = f"{log_file.stem}_{timestamp}.log.gz"
        archive_path = self.archive_dir / archive_name
        
        try:
            # Compress and move to archive
            with open(log_file, 'rb') as f_in:
                with gzip.open(archive_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Clear original file (don't delete, just truncate)
            with open(log_file, 'w') as f:
                f.write(f"# Log rotated at {datetime.now().isoformat()}\n")
            
            logger.info(f"Rotated log: {log_file.name} -> {archive_name}")
            return archive_path
            
        except Exception as e:
            logger.error(f"Failed to rotate log {log_file}: {e}")
            return None
    
    def cleanup_old_logs(self, retention_days: int = LOG_RETENTION_DAYS) -> CleanupResult:
        """
        Delete log files older than retention period
        
        Steps:
        1. Calculate cutoff date
        2. Find all .log files
        3. Check modification time
        4. Delete if older than cutoff
        """
        result = CleanupResult(
            operation='log_cleanup',
            files_processed=0,
            files_deleted=0,
            files_archived=0,
            bytes_freed=0,
            errors=[],
            timestamp=datetime.utcnow().isoformat()
        )
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            log_files = list(self.log_dir.glob('*.log'))
            result.files_processed = len(log_files)
            
            for log_file in log_files:
                try:
                    # Get file modification time
                    mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                    
                    if mtime < cutoff_date:
                        # File is old, delete it
                        file_size = log_file.stat().st_size
                        log_file.unlink()
                        result.files_deleted += 1
                        result.bytes_freed += file_size
                        logger.info(f"Deleted old log: {log_file.name}")
                        
                except Exception as e:
                    result.errors.append(f"Error processing {log_file}: {str(e)}")
                    logger.error(f"Error cleaning up {log_file}: {e}")
            
        except Exception as e:
            result.errors.append(f"Cleanup failed: {str(e)}")
            logger.error(f"Log cleanup failed: {e}")
        
        return result
    
    def cleanup_old_archives(self, retention_days: int = ARCHIVE_RETENTION_DAYS) -> CleanupResult:
        """Delete archived log files older than retention period"""
        result = CleanupResult(
            operation='archive_cleanup',
            files_processed=0,
            files_deleted=0,
            files_archived=0,
            bytes_freed=0,
            errors=[],
            timestamp=datetime.utcnow().isoformat()
        )
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            archive_files = list(self.archive_dir.glob('*.gz'))
            result.files_processed = len(archive_files)
            
            for archive_file in archive_files:
                try:
                    mtime = datetime.fromtimestamp(archive_file.stat().st_mtime)
                    
                    if mtime < cutoff_date:
                        file_size = archive_file.stat().st_size
                        archive_file.unlink()
                        result.files_deleted += 1
                        result.bytes_freed += file_size
                        logger.info(f"Deleted old archive: {archive_file.name}")
                        
                except Exception as e:
                    result.errors.append(f"Error processing {archive_file}: {str(e)}")
            
        except Exception as e:
            result.errors.append(f"Archive cleanup failed: {str(e)}")
        
        return result
    
    def get_log_stats(self) -> Dict:
        """Get statistics about log files"""
        stats = {
            'total_log_files': 0,
            'total_log_size': 0,
            'total_archive_files': 0,
            'total_archive_size': 0,
            'oldest_log': None,
            'newest_log': None
        }
        
        # Log files
        log_files = list(self.log_dir.glob('*.log'))
        stats['total_log_files'] = len(log_files)
        
        for log_file in log_files:
            size = log_file.stat().st_size
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
            stats['total_log_size'] += size
            
            if stats['oldest_log'] is None or mtime < stats['oldest_log']:
                stats['oldest_log'] = mtime
            if stats['newest_log'] is None or mtime > stats['newest_log']:
                stats['newest_log'] = mtime
        
        # Archive files
        archive_files = list(self.archive_dir.glob('*.gz'))
        stats['total_archive_files'] = len(archive_files)
        
        for archive_file in archive_files:
            stats['total_archive_size'] += archive_file.stat().st_size
        
        # Format sizes
        stats['total_log_size_human'] = self._format_bytes(stats['total_log_size'])
        stats['total_archive_size_human'] = self._format_bytes(stats['total_archive_size'])
        
        return stats
    
    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"


class IOCRetentionManager:
    """Manages IOC database retention and cleanup"""
    
    def __init__(self, db_path: Optional[Path] = None):
        from ioc_tracker import IOC_DB_PATH
        self.db_path = db_path or IOC_DB_PATH
    
    def cleanup_old_iocs(self, retention_days: int = IOC_RETENTION_DAYS) -> CleanupResult:
        """
        Delete old IOC records from database
        
        Strategy:
        1. Keep blocked IPs indefinitely (security)
        2. Delete non-blocked IOCs older than retention period
        3. Delete old attack logs
        """
        result = CleanupResult(
            operation='ioc_cleanup',
            files_processed=0,
            files_deleted=0,
            files_archived=0,
            bytes_freed=0,
            errors=[],
            timestamp=datetime.utcnow().isoformat()
        )
        
        cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Count total IOCs before cleanup
            cursor.execute('SELECT COUNT(*) FROM iocs')
            result.files_processed = cursor.fetchone()[0]
            
            # Delete old attack logs first (foreign key constraint)
            cursor.execute('DELETE FROM attack_logs WHERE timestamp < ?', (cutoff_date,))
            logs_deleted = cursor.rowcount
            
            # Delete old IOCs that are not blocked
            cursor.execute('''
                DELETE FROM iocs 
                WHERE last_seen < ? AND blocked = 0
            ''', (cutoff_date,))
            iocs_deleted = cursor.rowcount
            
            result.files_deleted = iocs_deleted
            
            conn.commit()
            conn.close()
            
            logger.info(f"Cleaned up {iocs_deleted} IOCs and {logs_deleted} attack logs")
            
        except Exception as e:
            result.errors.append(f"IOC cleanup failed: {str(e)}")
            logger.error(f"IOC cleanup failed: {e}")
        
        return result
    
    def export_iocs_to_json(self, output_file: Path) -> bool:
        """Export all IOCs to JSON file for backup"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM iocs')
            iocs = [dict(row) for row in cursor.fetchall()]
            
            with open(output_file, 'w') as f:
                json.dump(iocs, f, indent=2, default=str)
            
            conn.close()
            logger.info(f"Exported {len(iocs)} IOCs to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export IOCs: {e}")
            return False
    
    def get_ioc_stats(self) -> Dict:
        """Get IOC database statistics"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            stats = {}
            
            # Total IOCs
            cursor.execute('SELECT COUNT(*) FROM iocs')
            stats['total_iocs'] = cursor.fetchone()[0]
            
            # Blocked IOCs
            cursor.execute('SELECT COUNT(*) FROM iocs WHERE blocked = 1')
            stats['blocked_iocs'] = cursor.fetchone()[0]
            
            # Suspicious IOCs
            cursor.execute('SELECT COUNT(*) FROM iocs WHERE suspicious = 1')
            stats['suspicious_iocs'] = cursor.fetchone()[0]
            
            # Database size
            cursor.execute("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()")
            db_size = cursor.fetchone()[0]
            stats['database_size_bytes'] = db_size
            stats['database_size_human'] = self._format_bytes(db_size)
            
            conn.close()
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get IOC stats: {e}")
            return {}
    
    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"


class SessionRetentionManager:
    """Manages session file cleanup"""
    
    def __init__(self, sessions_dir: Path = DATA_DIR / 'sessions'):
        self.sessions_dir = sessions_dir
    
    def cleanup_old_sessions(self, retention_days: int = LOG_RETENTION_DAYS) -> CleanupResult:
        """Delete old session JSON files"""
        result = CleanupResult(
            operation='session_cleanup',
            files_processed=0,
            files_deleted=0,
            files_archived=0,
            bytes_freed=0,
            errors=[],
            timestamp=datetime.utcnow().isoformat()
        )
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            session_files = list(self.sessions_dir.glob('*.json'))
            result.files_processed = len(session_files)
            
            for session_file in session_files:
                try:
                    mtime = datetime.fromtimestamp(session_file.stat().st_mtime)
                    
                    if mtime < cutoff_date:
                        file_size = session_file.stat().st_size
                        session_file.unlink()
                        result.files_deleted += 1
                        result.bytes_freed += file_size
                        
                except Exception as e:
                    result.errors.append(f"Error deleting {session_file}: {str(e)}")
            
            logger.info(f"Cleaned up {result.files_deleted} old session files")
            
        except Exception as e:
            result.errors.append(f"Session cleanup failed: {str(e)}")
        
        return result


class AutomatedCleanupScheduler:
    """Schedules and runs automated cleanup tasks"""
    
    def __init__(self):
        self.log_manager = LogRetentionManager()
        self.ioc_manager = IOCRetentionManager()
        self.session_manager = SessionRetentionManager()
        self.running = False
        self.scheduler_thread = None
    
    def run_cleanup(self) -> Dict:
        """Run all cleanup operations"""
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'operations': []
        }
        
        logger.info("Starting automated cleanup...")
        
        # Cleanup old logs
        log_result = self.log_manager.cleanup_old_logs()
        results['operations'].append(log_result.to_dict())
        
        # Cleanup old archives
        archive_result = self.log_manager.cleanup_old_archives()
        results['operations'].append(archive_result.to_dict())
        
        # Cleanup old IOCs
        ioc_result = self.ioc_manager.cleanup_old_iocs()
        results['operations'].append(ioc_result.to_dict())
        
        # Cleanup old sessions
        session_result = self.session_manager.cleanup_old_sessions()
        results['operations'].append(session_result.to_dict())
        
        # Calculate totals
        total_deleted = sum(op['files_deleted'] for op in results['operations'])
        total_freed = sum(op['bytes_freed'] for op in results['operations'])
        
        results['summary'] = {
            'total_files_deleted': total_deleted,
            'total_bytes_freed': total_freed,
            'total_bytes_freed_human': self._format_bytes(total_freed)
        }
        
        logger.info(f"Cleanup complete. Deleted {total_deleted} files, freed {self._format_bytes(total_freed)}")
        
        return results
    
    def schedule_cleanup(self, time_str: str = CLEANUP_SCHEDULE):
        """Schedule daily cleanup at specified time"""
        schedule.clear()
        schedule.every().day.at(time_str).do(self.run_cleanup)
        logger.info(f"Scheduled daily cleanup at {time_str}")
    
    def start_scheduler(self):
        """Start the cleanup scheduler in background thread"""
        if self.running:
            return
        
        self.running = True
        self.schedule_cleanup()
        
        def run_scheduler():
            while self.running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        self.scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        self.scheduler_thread.start()
        logger.info("Cleanup scheduler started")
    
    def stop_scheduler(self):
        """Stop the cleanup scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Cleanup scheduler stopped")
    
    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"


# Convenience functions
def run_manual_cleanup() -> Dict:
    """Run cleanup manually (for CLI or API call)"""
    scheduler = AutomatedCleanupScheduler()
    return scheduler.run_cleanup()


def get_storage_stats() -> Dict:
    """Get comprehensive storage statistics"""
    log_manager = LogRetentionManager()
    ioc_manager = IOCRetentionManager()
    
    return {
        'logs': log_manager.get_log_stats(),
        'iocs': ioc_manager.get_ioc_stats(),
        'retention_settings': {
            'log_retention_days': LOG_RETENTION_DAYS,
            'ioc_retention_days': IOC_RETENTION_DAYS,
            'archive_retention_days': ARCHIVE_RETENTION_DAYS
        }
    }


# Example usage
if __name__ == '__main__':
    print("Testing Retention Manager...")
    
    # Test log stats
    log_mgr = LogRetentionManager()
    stats = log_mgr.get_log_stats()
    print(f"\nLog Statistics:")
    print(f"  Log files: {stats['total_log_files']}")
    print(f"  Total size: {stats.get('total_log_size_human', '0 B')}")
    
    # Test cleanup (dry run - just show what would be deleted)
    print(f"\nRunning cleanup (retention: {LOG_RETENTION_DAYS} days)...")
    result = log_mgr.cleanup_old_logs()
    print(f"  Files processed: {result.files_processed}")
    print(f"  Files deleted: {result.files_deleted}")
    print(f"  Bytes freed: {result.bytes_freed}")
    
    # Test IOC stats
    ioc_mgr = IOCRetentionManager()
    ioc_stats = ioc_mgr.get_ioc_stats()
    print(f"\nIOC Statistics:")
    print(f"  Total IOCs: {ioc_stats.get('total_iocs', 0)}")
    print(f"  Database size: {ioc_stats.get('database_size_human', '0 B')}")
    
    print("\nRetention Manager test complete!")
