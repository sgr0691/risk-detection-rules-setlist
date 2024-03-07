from collections import defaultdict


def detect_failed_logins_by_user(logs, threshold=3):
    """
    Detect multiple failed login attempts for the same user from the same IP address.

    Args:
    - logs: A list of dictionaries, each representing a login attempt.
    - threshold: The number of failed attempts to trigger an alert.

    Returns:
    - A dictionary with tuples (IP address, username) as keys and the count of failed attempts as values.
    """
    failed_attempts = defaultdict(int)
    for log in logs:
        if log['event'] == 'login_failed':
            key = (log['ip_address'], log['username'])
            failed_attempts[key] += 1

    return {key: count for key, count in failed_attempts.items() if count >= threshold}

# Example usage
flagged_attempts_by_user = detect_failed_logins_by_user(logs)
print("Flagged (IP, user) for multiple failed login attempts:", flagged_attempts_by_user)
