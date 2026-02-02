# =========================================
# SecureProbe - Advanced Attack Filtering
# Optimized | SOC / MITRE Style
# =========================================

import logging
import re
from collections import defaultdict

# -------------------------------------------------
# Attack Patterns (Regex-based, Categorized)
# -------------------------------------------------
ATTACK_PATTERNS = {
    # ===== Reconnaissance =====
    r"nmap scan": ("Reconnaissance", "Network Scanning"),
    r"masscan": ("Reconnaissance", "High-Speed Port Scanning"),
    r"service enumeration": ("Reconnaissance", "Service Enumeration"),
    r"banner grabbing": ("Reconnaissance", "Banner Grabbing"),
    r"whois lookup": ("Reconnaissance", "OSINT Reconnaissance"),

    # ===== Credential Access =====
    r"failed password": ("Credential Access", "SSH Brute Force"),
    r"invalid user": ("Credential Access", "User Enumeration"),
    r"password spraying": ("Credential Access", "Password Spraying"),
    r"authentication failure": ("Credential Access", "Login Brute Force"),

    # ===== Initial Access =====
    r"union select": ("Initial Access", "SQL Injection"),
    r"' or 1=1": ("Initial Access", "SQL Injection"),
    r"<script>": ("Initial Access", "Cross-Site Scripting (XSS)"),
    r"\.\./": ("Initial Access", "Path Traversal"),
    r"file upload": ("Initial Access", "Malicious File Upload"),

    # ===== Execution =====
    r"shellcode": ("Execution", "Remote Code Execution"),
    r"command execution": ("Execution", "Command Injection"),
    r"powershell -enc": ("Execution", "Encoded PowerShell Execution"),
    r"bash -c": ("Execution", "Shell Command Execution"),

    # ===== Persistence =====
    r"cron job added": ("Persistence", "Cron Job Persistence"),
    r"startup script modified": ("Persistence", "Startup Script Persistence"),
    r"registry run key": ("Persistence", "Registry Autorun"),

    # ===== Privilege Escalation =====
    r"sudo abuse": ("Privilege Escalation", "Sudo Abuse"),
    r"permission denied": ("Privilege Escalation", "Privilege Escalation Attempt"),
    r"setuid": ("Privilege Escalation", "SUID Abuse"),

    # ===== Lateral Movement =====
    r"psexec": ("Lateral Movement", "PsExec Execution"),
    r"wmic process call": ("Lateral Movement", "WMIC Execution"),
    r"smb authentication failed": ("Lateral Movement", "SMB Lateral Movement"),
    r"rdp login failed": ("Lateral Movement", "RDP Credential Attack"),

    # ===== Command & Control =====
    r"beaconing": ("Command and Control", "C2 Beaconing"),
    r"suspicious dns request": ("Command and Control", "DNS Tunneling"),
    r"outbound connection to unknown ip": ("Command and Control", "External C2 Communication"),

    # ===== Exfiltration =====
    r"large outbound transfer": ("Exfiltration", "Data Exfiltration"),
    r"unauthorized data upload": ("Exfiltration", "Data Leakage"),
    r"ftp upload": ("Exfiltration", "FTP Data Exfiltration"),

    # ===== Impact =====
    r"syn flood": ("Impact", "SYN Flood DDoS"),
    r"udp flood": ("Impact", "UDP Flood DDoS"),
    r"too many requests": ("Impact", "Application Layer DDoS"),
    r"service unavailable": ("Impact", "Service Disruption"),

    # ===== Cloud & Container =====
    r"docker api exposed": ("Cloud", "Docker API Exploitation"),
    r"kube-apiserver": ("Cloud", "Kubernetes API Abuse"),
    r"unauthorized api call": ("Cloud", "Cloud API Abuse"),

    # ===== Malware =====
    r"malware signature": ("Malware", "Malware Detected"),
    r"trojan detected": ("Malware", "Trojan Activity"),
    r"ransom note": ("Malware", "Ransomware Indicator"),
}

# -------------------------------------------------
# Compile regex patterns once (performance)
# -------------------------------------------------
COMPILED_PATTERNS = {
    re.compile(pattern, re.IGNORECASE): meta
    for pattern, meta in ATTACK_PATTERNS.items()
}

# -------------------------------------------------
# Attack Filtering Function
# -------------------------------------------------
def filter_attacks(log_file_path):
    """
    Reads a log file and detects attacks using
    regex-based SOC-style correlation.
    """

    logging.info("Attack filtering started")

    attack_summary = defaultdict(lambda: {
        "category": "",
        "count": 0
    })

    try:
        with open(log_file_path, "r", errors="ignore") as logfile:
            for line in logfile:
                for regex, (category, name) in COMPILED_PATTERNS.items():
                    if regex.search(line):
                        key = f"[{category}] {name}"
                        attack_summary[key]["category"] = category
                        attack_summary[key]["count"] += 1
                        logging.warning(f"Detected attack: {key}")

    except FileNotFoundError:
        logging.error("Log file not found")
        return []

    logging.info("Attack filtering completed")

    # Format output
    results = []
    for attack, data in attack_summary.items():
        results.append(
            f"{attack} | Occurrences: {data['count']}"
        )

    return results
