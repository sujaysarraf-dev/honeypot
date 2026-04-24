#!/usr/bin/env python3
"""
Logging Middleware - Comprehensive request/response logging system
Logs all HTTP requests with structured JSON format
"""

import json
import logging
import time
import uuid
import os
import re
from datetime import datetime
from pathlib import Path
from functools import wraps
from flask import request, g, has_request_context
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Configuration from environment
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')  # json or text
LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', '10485760'))  # 10MB
LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))
LOG_DIR = Path(os.getenv('LOG_DIR', '/logs'))

# Ensure log directory exists
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass # Directory is probably read-only and already exists

# IOC Patterns for detection
IOC_PATTERNS = {
    'sql_injection': [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION\s+SELECT",
        r"INSERT\s+INTO",
        r"DELETE\s+FROM",
        r"DROP\s+TABLE",
    ],
    'xss': [
        r"((\%3C)|<)[^\n]+((\%3E)|>)",
        r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
        r"((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)",
        r"javascript:",
        r"on\w+\s*=",
        r"<script[^>]*>[\s\S]*?</script>",
    ],
    'path_traversal': [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        r"etc/passwd",
        r"etc/shadow",
        r"windows/system32",
        r"boot.ini",
    ],
    'command_injection': [
        r"[;&|`]\s*\w+",
        r"\$\(\s*\w+",
        r"`\s*\w+",
        r"\|\s*\w+",
        r"\/bin\/\w+",
        r"cmd\.exe",
        r"powershell",
        r"bash\s+-c",
    ],
    'ldap_injection': [
        r"\*\)\(\|\*",
        r"\*\)\(\&\*",
        r"\(\|\(\w+=\*",
        r"\(\&\(\w+=\*",
    ],
    'xml_injection': [
        r"<!ENTITY\s+\w+",
        r"<!DOCTYPE\s+\w+",
        r"SYSTEM\s+\"",
        r"PUBLIC\s+\"",
    ],
}


class StructuredLogFormatter(logging.Formatter):
    """Custom formatter for structured JSON logs"""
    
    def format(self, record):
        log_obj = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, 'request_id'):
            log_obj['request_id'] = record.request_id
        if hasattr(record, 'source_ip'):
            log_obj['source_ip'] = record.source_ip
        if hasattr(record, 'attack_type'):
            log_obj['attack_type'] = record.attack_type
        if hasattr(record, 'metadata') and record.metadata:
            log_obj.update(record.metadata)
        
        # Add exception info if present
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_obj, default=str)


def setup_logging(service_name='honeypot'):
    """Setup structured logging for the application"""
    
    # Create logger
    logger = logging.getLogger(service_name)
    logger.setLevel(getattr(logging, LOG_LEVEL.upper()))
    
    # Remove existing handlers
    logger.handlers = []
    
    # Create formatters
    if LOG_FORMAT == 'json':
        formatter = StructuredLogFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    try:
        # File handler with rotation by size
        file_handler = RotatingFileHandler(
            LOG_DIR / f'{service_name}.log',
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Time-based rotation for audit logs
        audit_handler = TimedRotatingFileHandler(
            LOG_DIR / f'{service_name}_audit.log',
            when='midnight',
            interval=1,
            backupCount=30
        )
        audit_handler.setFormatter(formatter)
        audit_handler.setLevel(logging.WARNING)
        logger.addHandler(audit_handler)
    except OSError:
        pass # Fallback to console logging if readonly
    
    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


# Global logger instance
logger = setup_logging()


def detect_attack_patterns(data):
    """Detect attack patterns in request data"""
    if not data:
        return []
    
    detected_attacks = []
    data_str = str(data)
    
    for attack_type, patterns in IOC_PATTERNS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, data_str, re.IGNORECASE):
                    detected_attacks.append({
                        'type': attack_type,
                        'pattern': pattern,
                        'matched_data': data_str[:200]  # Truncate for safety
                    })
                    break  # Only report once per attack type
            except re.error:
                continue
    
    return detected_attacks


def get_client_ip():
    """Get client IP address from request"""
    if has_request_context():
        # Check for forwarded IP (behind proxy)
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    return None


def get_request_body():
    """Safely get request body"""
    if not has_request_context():
        return None
    
    body = None
    
    # Try to get JSON data
    if request.is_json:
        try:
            body = request.get_json(silent=True)
        except:
            pass
    
    # Try to get form data
    if body is None and request.form:
        body = dict(request.form)
    
    # Try to get raw data
    if body is None:
        try:
            body = request.get_data(as_text=True)
            if body:
                # Try to parse as JSON
                try:
                    body = json.loads(body)
                except:
                    pass
        except:
            pass
    
    return body


def sanitize_sensitive_data(data):
    """Remove sensitive fields from logged data"""
    if not isinstance(data, dict):
        return data
    
    sensitive_fields = ['password', 'token', 'secret', 'api_key', 'authorization', 'cookie']
    sanitized = {}
    
    for key, value in data.items():
        if any(field in key.lower() for field in sensitive_fields):
            sanitized[key] = '***REDACTED***'
        elif isinstance(value, dict):
            sanitized[key] = sanitize_sensitive_data(value)
        elif isinstance(value, list):
            sanitized[key] = [sanitize_sensitive_data(item) if isinstance(item, dict) else item for item in value]
        else:
            sanitized[key] = value
    
    return sanitized


class RequestLogger:
    """Middleware to log all HTTP requests"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        
        @app.before_request
        def before_request():
            # Generate unique request ID
            g.request_id = str(uuid.uuid4())
            g.request_start_time = time.time()
            
            # Get request details
            g.client_ip = get_client_ip()
            g.request_body = get_request_body()
            
            # Detect attacks in request
            g.detected_attacks = []
            
            # Check URL
            url_attacks = detect_attack_patterns(request.url)
            g.detected_attacks.extend(url_attacks)
            
            # Check query parameters
            if request.args:
                query_attacks = detect_attack_patterns(dict(request.args))
                g.detected_attacks.extend(query_attacks)
            
            # Check body
            if g.request_body:
                body_attacks = detect_attack_patterns(g.request_body)
                g.detected_attacks.extend(body_attacks)
            
            # Check headers (common attack vectors)
            header_attacks = detect_attack_patterns(dict(request.headers))
            g.detected_attacks.extend(header_attacks)
            
            # Log request
            self.log_request()
        
        @app.after_request
        def after_request(response):
            # Calculate response time
            response_time = time.time() - g.request_start_time
            
            # Log response
            self.log_response(response, response_time)
            
            # Add security headers
            response.headers['X-Request-ID'] = g.request_id
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            return response
        
        @app.errorhandler(Exception)
        def handle_exception(e):
            # Log the error
            logger.error(
                f"Unhandled exception: {str(e)}",
                extra={
                    'request_id': getattr(g, 'request_id', 'unknown'),
                    'source_ip': getattr(g, 'client_ip', 'unknown'),
                    'metadata': {
                        'exception_type': type(e).__name__,
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'url': request.url
                    }
                }
            )
            raise e
    
    def log_request(self):
        """Log incoming request details"""
        if not has_request_context():
            return
        
        # Sanitize headers
        headers = dict(request.headers)
        headers = sanitize_sensitive_data(headers)
        
        # Sanitize body
        body = sanitize_sensitive_data(g.request_body) if g.request_body else None
        
        log_data = {
            'request_id': g.request_id,
            'source_ip': g.client_ip,
            'metadata': {
                'event_type': 'request',
                'method': request.method,
                'url': request.url,
                'path': request.path,
                'endpoint': request.endpoint,
                'query_params': dict(request.args),
                'headers': headers,
                'body': body,
                'user_agent': request.headers.get('User-Agent'),
                'referrer': request.headers.get('Referer'),
                'content_type': request.content_type,
                'content_length': request.content_length,
                'detected_attacks': g.detected_attacks if g.detected_attacks else None
            }
        }
        
        # Log at appropriate level based on attacks detected
        if g.detected_attacks:
            logger.warning(
                f"Request with detected attacks: {[a['type'] for a in g.detected_attacks]}",
                extra=log_data
            )
        else:
            logger.info(
                f"Request: {request.method} {request.path}",
                extra=log_data
            )
    
    def log_response(self, response, response_time):
        """Log outgoing response details"""
        if not has_request_context():
            return
        
        log_data = {
            'request_id': g.request_id,
            'source_ip': g.client_ip,
            'metadata': {
                'event_type': 'response',
                'status_code': response.status_code,
                'response_time_ms': round(response_time * 1000, 2),
                'content_type': response.content_type,
                'content_length': response.content_length,
                'detected_attacks': g.detected_attacks if g.detected_attacks else None
            }
        }
        
        # Log at appropriate level
        if response.status_code >= 500:
            logger.error(
                f"Server error: {response.status_code}",
                extra=log_data
            )
        elif response.status_code >= 400:
            logger.warning(
                f"Client error: {response.status_code}",
                extra=log_data
            )
        elif g.detected_attacks:
            logger.warning(
                f"Response to attack attempt: {response.status_code}",
                extra=log_data
            )
        else:
            logger.info(
                f"Response: {response.status_code} in {response_time*1000:.2f}ms",
                extra=log_data
            )


def log_security_event(event_type, details, severity='warning'):
    """Log security-related events"""
    log_func = getattr(logger, severity.lower(), logger.warning)
    
    log_func(
        f"Security event: {event_type}",
        extra={
            'request_id': getattr(g, 'request_id', str(uuid.uuid4())),
            'source_ip': get_client_ip(),
            'metadata': {
                'event_type': 'security',
                'security_event_type': event_type,
                'details': details,
                'severity': severity
            }
        }
    )


def log_attack_detected(attack_type, details, source_ip=None):
    """Specifically log detected attacks"""
    logger.warning(
        f"Attack detected: {attack_type}",
        extra={
            'request_id': getattr(g, 'request_id', str(uuid.uuid4())),
            'source_ip': source_ip or get_client_ip(),
            'attack_type': attack_type,
            'metadata': {
                'event_type': 'attack_detected',
                'attack_type': attack_type,
                'details': details,
                'timestamp': datetime.utcnow().isoformat()
            }
        }
    )


# Decorator for logging function calls
def log_function_call(func):
    """Decorator to log function entry and exit"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        start_time = time.time()
        
        logger.debug(f"Entering {func_name}", extra={
            'metadata': {
                'event_type': 'function_call',
                'function': func_name,
                'args_count': len(args),
                'kwargs_keys': list(kwargs.keys())
            }
        })
        
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            logger.debug(f"Exiting {func_name} in {execution_time:.3f}s", extra={
                'metadata': {
                    'event_type': 'function_return',
                    'function': func_name,
                    'execution_time': execution_time,
                    'success': True
                }
            })
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            logger.error(f"Exception in {func_name}: {str(e)}", extra={
                'metadata': {
                    'event_type': 'function_error',
                    'function': func_name,
                    'execution_time': execution_time,
                    'error': str(e),
                    'error_type': type(e).__name__
                }
            })
            
            raise
    
    return wrapper


# Example usage and testing
if __name__ == '__main__':
    # Test logging
    print("Testing logging system...")
    
    # Test basic logging
    logger.info("Test info message")
    logger.warning("Test warning message")
    logger.error("Test error message")
    
    # Test attack detection
    test_payloads = [
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "; cat /etc/passwd",
        "normal_input_here"
    ]
    
    for payload in test_payloads:
        attacks = detect_attack_patterns(payload)
        if attacks:
            print(f"Detected attacks in '{payload[:30]}...': {[a['type'] for a in attacks]}")
        else:
            print(f"No attacks detected in: {payload}")
    
    print("\nLogging system test complete!")
    print(f"Logs written to: {LOG_DIR}")
