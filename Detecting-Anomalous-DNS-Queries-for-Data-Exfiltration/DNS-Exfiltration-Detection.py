from collections import defaultdict
import re

def detect_dns_exfiltration(dns_logs, threshold_frequency=10, rare_domain_threshold=2, query_length_threshold=50):
    """
    Detect potential DNS exfiltration based on frequency, domain rarity, and query length.

    Args:
    - dns_logs: List of dictionaries representing DNS query logs.
    - threshold_frequency: The threshold of queries per minute considered suspicious.
    - rare_domain_threshold: The threshold for considering a domain as rare.
    - query_length_threshold: The threshold for considering a DNS query unusually long.

    Returns:
    - List of suspicious DNS queries.
    """
    suspicious_queries = []
    domain_frequency = defaultdict(int)
    query_lengths = defaultdict(list)

    # Count domain frequencies and query lengths
    for log in dns_logs:
        domain_frequency[log['domain']] += 1
        query_lengths[log['domain']].append(len(log['query']))

    # Identify rare domains with high query frequencies or long query strings
    for domain, freq in domain_frequency.items():
        if freq > threshold_frequency:
            avg_length = sum(query_lengths[domain]) / len(query_lengths[domain])
            if len(domain_frequency) > rare_domain_threshold or avg_length > query_length_threshold:
                suspicious_queries.append({'domain': domain, 'frequency': freq, 'average_length': avg_length})

    return suspicious_queries
