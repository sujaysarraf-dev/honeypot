#!/usr/bin/env python3
"""
Mock API for Threat Data
Provides sample threat data for testing the dashboard maps
"""

import random
import json
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

mock_api = Blueprint('mock_api', __name__)

# Sample threat data with realistic locations
SAMPLE_THREATS = [
    {
        "id": "threat_001",
        "ip": "192.168.1.100",
        "country": "CN",
        "country_name": "China",
        "city": "Beijing",
        "lat": 39.9042,
        "lng": 116.4074,
        "attack_type": "brute_force",
        "severity": "high",
        "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
        "target": "SSH",
        "attempts": 45
    },
    {
        "id": "threat_002",
        "ip": "10.0.0.50",
        "country": "RU",
        "country_name": "Russia",
        "city": "Moscow",
        "lat": 55.7558,
        "lng": 37.6173,
        "attack_type": "sql_injection",
        "severity": "critical",
        "timestamp": (datetime.utcnow() - timedelta(minutes=12)).isoformat(),
        "target": "HTTP",
        "attempts": 12
    },
    {
        "id": "threat_003",
        "ip": "172.16.0.25",
        "country": "US",
        "country_name": "United States",
        "city": "New York",
        "lat": 40.7128,
        "lng": -74.0060,
        "attack_type": "xss",
        "severity": "medium",
        "timestamp": (datetime.utcnow() - timedelta(minutes=18)).isoformat(),
        "target": "HTTP",
        "attempts": 8
    },
    {
        "id": "threat_004",
        "ip": "203.0.113.75",
        "country": "BR",
        "country_name": "Brazil",
        "city": "São Paulo",
        "lat": -23.5505,
        "lng": -46.6333,
        "attack_type": "path_traversal",
        "severity": "high",
        "timestamp": (datetime.utcnow() - timedelta(minutes=25)).isoformat(),
        "target": "HTTP",
        "attempts": 23
    },
    {
        "id": "threat_005",
        "ip": "198.51.100.42",
        "country": "DE",
        "country_name": "Germany",
        "city": "Berlin",
        "lat": 52.5200,
        "lng": 13.4050,
        "attack_type": "command_injection",
        "severity": "critical",
        "timestamp": (datetime.utcnow() - timedelta(minutes=32)).isoformat(),
        "target": "HTTP",
        "attempts": 6
    },
    {
        "id": "threat_006",
        "ip": "192.0.2.88",
        "country": "IN",
        "country_name": "India",
        "city": "Mumbai",
        "lat": 19.0760,
        "lng": 72.8777,
        "attack_type": "brute_force",
        "severity": "medium",
        "timestamp": (datetime.utcnow() - timedelta(minutes=45)).isoformat(),
        "target": "FTP",
        "attempts": 67
    },
    {
        "id": "threat_007",
        "ip": "185.220.101.33",
        "country": "NL",
        "country_name": "Netherlands",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lng": 4.9041,
        "attack_type": "port_scan",
        "severity": "low",
        "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
        "target": "Network",
        "attempts": 150
    },
    {
        "id": "threat_008",
        "ip": "103.21.244.15",
        "country": "JP",
        "country_name": "Japan",
        "city": "Tokyo",
        "lat": 35.6762,
        "lng": 139.6503,
        "attack_type": "ddos",
        "severity": "critical",
        "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
        "target": "HTTP",
        "attempts": 5000
    },
    {
        "id": "threat_009",
        "ip": "91.198.174.192",
        "country": "GB",
        "country_name": "United Kingdom",
        "city": "London",
        "lat": 51.5074,
        "lng": -0.1278,
        "attack_type": "credential_stuffing",
        "severity": "high",
        "timestamp": (datetime.utcnow() - timedelta(hours=3)).isoformat(),
        "target": "HTTP",
        "attempts": 234
    },
    {
        "id": "threat_010",
        "ip": "197.234.56.78",
        "country": "ZA",
        "country_name": "South Africa",
        "city": "Cape Town",
        "lat": -33.9249,
        "lng": 18.4241,
        "attack_type": "malware_drop",
        "severity": "critical",
        "timestamp": (datetime.utcnow() - timedelta(hours=4)).isoformat(),
        "target": "SMB",
        "attempts": 3
    }
]

# Additional random threat generator
ATTACK_TYPES = [
    ('brute_force', 'medium'),
    ('sql_injection', 'critical'),
    ('xss', 'medium'),
    ('path_traversal', 'high'),
    ('command_injection', 'critical'),
    ('port_scan', 'low'),
    ('ddos', 'critical'),
    ('credential_stuffing', 'high'),
    ('malware_drop', 'critical')
]

COUNTRIES = [
    ('CN', 'China', 35.8617, 104.1954),
    ('RU', 'Russia', 61.5240, 105.3188),
    ('US', 'United States', 37.0902, -95.7129),
    ('BR', 'Brazil', -14.2350, -51.9253),
    ('DE', 'Germany', 51.1657, 10.4515),
    ('IN', 'India', 20.5937, 78.9629),
    ('GB', 'United Kingdom', 55.3781, -3.4360),
    ('FR', 'France', 46.2276, 2.2137),
    ('JP', 'Japan', 36.2048, 138.2529),
    ('KR', 'South Korea', 35.9078, 127.7669),
    ('IR', 'Iran', 32.4279, 53.6880),
    ('VN', 'Vietnam', 14.0583, 108.2772),
    ('ID', 'Indonesia', -0.7893, 113.9213),
    ('TR', 'Turkey', 38.9637, 35.2433),
    ('EG', 'Egypt', 26.8206, 30.8025),
    ('NG', 'Nigeria', 9.0820, 8.6753),
    ('PK', 'Pakistan', 30.3753, 69.3451),
    ('BD', 'Bangladesh', 23.6850, 90.3563),
    ('UA', 'Ukraine', 48.3794, 31.1656),
    ('PL', 'Poland', 51.9194, 19.1451)
]


def generate_random_threat():
    """Generate a random threat entry"""
    country_code, country_name, base_lat, base_lng = random.choice(COUNTRIES)
    attack_type, severity = random.choice(ATTACK_TYPES)
    
    # Add some randomness to coordinates
    lat = base_lat + random.uniform(-5, 5)
    lng = base_lng + random.uniform(-5, 5)
    
    return {
        "id": f"threat_{random.randint(1000, 9999)}",
        "ip": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
        "country": country_code,
        "country_name": country_name,
        "city": "Unknown",
        "lat": round(lat, 4),
        "lng": round(lng, 4),
        "attack_type": attack_type,
        "severity": severity,
        "timestamp": (datetime.utcnow() - timedelta(minutes=random.randint(1, 300))).isoformat(),
        "target": random.choice(["HTTP", "SSH", "FTP", "SMB", "Database"]),
        "attempts": random.randint(1, 500)
    }


@mock_api.route('/api/threats', methods=['GET'])
def get_threats():
    """Get current threat data"""
    # Generate some random threats to simulate real-time data
    num_random = random.randint(3, 8)
    all_threats = SAMPLE_THREATS + [generate_random_threat() for _ in range(num_random)]
    
    # Sort by timestamp (newest first)
    all_threats.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        'status': 'success',
        'count': len(all_threats),
        'threats': all_threats,
        'generated_at': datetime.utcnow().isoformat()
    })


@mock_api.route('/api/threats/live', methods=['GET'])
def get_live_threats():
    """Get live/recent threat data (last 5 minutes)"""
    threats = []
    
    # Generate 1-3 new threats
    for _ in range(random.randint(1, 3)):
        threat = generate_random_threat()
        threat['timestamp'] = datetime.utcnow().isoformat()
        threats.append(threat)
    
    return jsonify({
        'status': 'success',
        'count': len(threats),
        'threats': threats,
        'timestamp': datetime.utcnow().isoformat()
    })


@mock_api.route('/api/threats/stats', methods=['GET'])
def get_threat_stats():
    """Get threat statistics"""
    # Generate random stats
    stats = {
        'total_threats_today': random.randint(150, 500),
        'active_threats': random.randint(10, 50),
        'blocked_attacks': random.randint(1000, 5000),
        'unique_attackers': random.randint(50, 200),
        'top_attack_types': [
            {'type': 'brute_force', 'count': random.randint(50, 150)},
            {'type': 'sql_injection', 'count': random.randint(20, 80)},
            {'type': 'xss', 'count': random.randint(30, 100)},
            {'type': 'port_scan', 'count': random.randint(40, 120)}
        ],
        'top_countries': [
            {'country': 'CN', 'count': random.randint(30, 80)},
            {'country': 'RU', 'count': random.randint(25, 70)},
            {'country': 'US', 'count': random.randint(20, 60)},
            {'country': 'BR', 'count': random.randint(15, 50)}
        ],
        'severity_breakdown': {
            'critical': random.randint(10, 40),
            'high': random.randint(30, 80),
            'medium': random.randint(50, 120),
            'low': random.randint(40, 100)
        },
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return jsonify({
        'status': 'success',
        'stats': stats
    })


@mock_api.route('/api/threats/country/<country_code>', methods=['GET'])
def get_country_threats(country_code):
    """Get threats for a specific country"""
    country_threats = [t for t in SAMPLE_THREATS if t['country'] == country_code.upper()]
    
    # Generate additional random threats for this country
    if country_threats:
        base_threat = country_threats[0]
        for _ in range(random.randint(2, 5)):
            threat = generate_random_threat()
            threat['country'] = country_code.upper()
            threat['country_name'] = base_threat['country_name']
            threat['lat'] = base_threat['lat'] + random.uniform(-2, 2)
            threat['lng'] = base_threat['lng'] + random.uniform(-2, 2)
            country_threats.append(threat)
    
    return jsonify({
        'status': 'success',
        'country': country_code.upper(),
        'count': len(country_threats),
        'threats': country_threats
    })


@mock_api.route('/api/attack-origins', methods=['GET'])
def get_attack_origins():
    """Get attack origin coordinates for map visualization"""
    origins = []
    
    for threat in SAMPLE_THREATS:
        origins.append({
            'lat': threat['lat'],
            'lng': threat['lng'],
            'country': threat['country'],
            'country_name': threat['country_name'],
            'attack_type': threat['attack_type'],
            'severity': threat['severity'],
            'intensity': random.uniform(0.3, 1.0)
        })
    
    # Add random origins
    for _ in range(random.randint(5, 15)):
        country_code, country_name, base_lat, base_lng = random.choice(COUNTRIES)
        attack_type, severity = random.choice(ATTACK_TYPES)
        origins.append({
            'lat': base_lat + random.uniform(-5, 5),
            'lng': base_lng + random.uniform(-5, 5),
            'country': country_code,
            'country_name': country_name,
            'attack_type': attack_type,
            'severity': severity,
            'intensity': random.uniform(0.1, 0.9)
        })
    
    return jsonify({
        'status': 'success',
        'count': len(origins),
        'origins': origins
    })


@mock_api.route('/api/attack-arcs', methods=['GET'])
def get_attack_arcs():
    """Get attack arc data for animated map lines"""
    # Target location (your honeypot)
    target_lat = 40.7128  # NYC
    target_lng = -74.0060
    
    arcs = []
    for threat in SAMPLE_THREATS[:5]:  # Limit to 5 for performance
        arcs.append({
            'from': {'lat': threat['lat'], 'lng': threat['lng']},
            'to': {'lat': target_lat, 'lng': target_lng},
            'country': threat['country'],
            'attack_type': threat['attack_type'],
            'severity': threat['severity'],
            'animate': True
        })
    
    return jsonify({
        'status': 'success',
        'count': len(arcs),
        'arcs': arcs,
        'target': {'lat': target_lat, 'lng': target_lng}
    })
