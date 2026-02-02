def get_advice(vulnerabilities):
    """
    Generates context-aware security recommendations
    based on detected vulnerabilities.
    """

    if not vulnerabilities:
        return "No vulnerabilities detected. System appears secure."

    advice = []
    advice.append("AI SECURITY ANALYSIS & RECOMMENDATIONS")
    advice.append("=" * 60)

    critical = []
    high = []
    medium = []

    # ------------------------------
    # Categorize by Severity
    # ------------------------------
    for v in vulnerabilities:
        if v["severity"] == "CRITICAL":
            critical.append(v)
        elif v["severity"] == "HIGH":
            high.append(v)
        else:
            medium.append(v)

    # ------------------------------
    # Detailed Analysis
    # ------------------------------
    for v in vulnerabilities:
        advice.append(
            f"\n[+] Port {v['port']} | {v['attack']} ({v['severity']})"
        )
        advice.append(f"Risk Description: {v.get('description', 'N/A')}")

        advice.append("Recommended Mitigations:")

        attack = v["attack"].lower()

        # ---- Web Attacks ----
        if any(x in attack for x in ["xss", "sql", "csrf", "idor", "injection"]):
            advice.extend([
                "- Implement strict input validation and output encoding",
                "- Deploy a Web Application Firewall (WAF)",
                "- Enforce secure session management",
                "- Perform regular code reviews and security testing"
            ])

        # ---- Network / Auth Attacks ----
        elif any(x in attack for x in ["ssh", "rdp", "brute", "smb", "ntlm"]):
            advice.extend([
                "- Restrict access using firewall and network segmentation",
                "- Enforce strong authentication and MFA",
                "- Disable legacy protocols and weak ciphers",
                "- Monitor authentication logs for anomalies"
            ])

        # ---- Database Attacks ----
        elif any(x in attack for x in ["mysql", "postgres", "mongo", "redis", "db"]):
            advice.extend([
                "- Restrict database access to internal networks only",
                "- Enable authentication and encryption",
                "- Apply least privilege on database users",
                "- Regularly audit database logs"
            ])

        # ---- Cloud / DevOps ----
        elif any(x in attack for x in ["docker", "kubernetes", "cloud", "api"]):
            advice.extend([
                "- Secure exposed APIs and management endpoints",
                "- Use IAM roles with least privilege",
                "- Enable audit logging and monitoring",
                "- Rotate secrets and credentials regularly"
            ])

        # ---- Generic Fallback ----
        else:
            advice.extend([
                "- Apply latest security patches",
                "- Restrict unnecessary network exposure",
                "- Enable centralized logging and monitoring"
            ])

    # ------------------------------
    # Risk Summary
    # ------------------------------
    advice.append("\n" + "-" * 60)
    advice.append("RISK PRIORITIZATION SUMMARY")
    advice.append("-" * 60)
    advice.append(f"Critical Issues : {len(critical)}")
    advice.append(f"High Risk Issues: {len(high)}")
    advice.append(f"Medium Issues   : {len(medium)}")

    # ------------------------------
    # Final Recommendation
    # ------------------------------
    advice.append("\nOVERALL RECOMMENDATION")
    advice.append(
        "Prioritize remediation of CRITICAL and HIGH risk vulnerabilities. "
        "Implement defense-in-depth strategies, continuous monitoring, "
        "and conduct periodic security assessments to reduce attack surface."
    )

    return "\n".join(advice)
