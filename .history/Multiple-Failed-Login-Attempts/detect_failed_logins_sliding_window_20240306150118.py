def detect_failed_logins_sliding_window(logs, threshold=3, window_size=timedelta(minutes=5)):
    """
    Detect multiple failed login attempts from the same IP address within a sliding time window.

    Args:
    - logs: A list of dictionaries, each representing a login attempt.
    - threshold: The number of failed attempts to trigger an alert.
    - window_size: The duration of the sliding window.

    Returns:
    - A list of IPs with multiple failed attempts within the time window.
    """
    flagged_attempts = []
    for index, log in enumerate(logs):
        current_time = datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S")
        count = 1
        for future_log in logs[index+1:]:
            future_time = datetime.strptime(future_log['timestamp'], "%Y-%m-%d %H:%M:%S")
            if future_log['ip_address'] == log['ip_address'] and future_time - current_time <= window_size:
                count += 1
        if count >= threshold:
            flagged_attempts.append(log['ip_address'])
    return set(flagged_attempts)
