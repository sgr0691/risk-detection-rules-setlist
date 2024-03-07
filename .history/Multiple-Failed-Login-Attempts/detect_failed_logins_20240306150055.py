from collections import defaultdict
from datetime import datetime, timedelta

# Simulated log entries
logs = [
    {"timestamp": "2024-03-01 10:00:00", "ip_address": "192.168.1.1", "event": "login_failed", "username": "user1"},
    {"timestamp": "2024-03-01 10:01:00", "ip_address": "192.168.1.2", "event": "login_failed", "username": "user2"},
    {"timestamp": "2024-03-01 10:01:30", "ip_address": "192.168.1.1", "event": "login_failed", "username": "user1"},
    {"timestamp": "2024-03-01 10:01:45", "ip_address": "192.168.1.1", "event": "login_failed", "username": "user1"},
    # Add more log entries as needed
]

def detect_failed_logins(logs, threshold=3):
    """
    Detect multiple failed login attempts from the same IP address.

    Args:
    - logs: A list of dictionaries, each representing a login attempt.
    - threshold: The number of failed attempts to trigger an alert.

    Returns:
    - A dictionary with IP addresses as keys and the count of failed attempts as values.
    """
    failed_attempts = defaultdict(int)
    for log in logs:
        if log['event'] == 'login_failed':
            failed_attempts[log['ip_address']] += 1

    return {ip: count for ip, count in failed_attempts.items() if count >= threshold}

# Detect multiple failed login attempts
flagged_attempts = detect_failed_logins(logs)
print("Flagged IPs for multiple failed login attempts:", flagged_attempts)
