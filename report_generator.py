# =========================================
# SecureProbe - Report Generator
# EC-Council Style Security Assessment Report
# =========================================

from datetime import datetime


def generate(scan_results, vulnerabilities, detected_attacks, ai_response):
    """
    Generates a detailed security assessment report.
    """

    with open("secureprobe_report.txt", "w") as report:
        # -------------------------------------------------
        # Header
        # -------------------------------------------------
        report.write("SECUREPROBE – SECURITY ASSESSMENT REPORT\n")
        report.write("=" * 70 + "\n")
        report.write(f"Generated On : {datetime.now()}\n\n")

        # -------------------------------------------------
        # Scan Summary
        # -------------------------------------------------
        report.write("1. SCAN SUMMARY\n")
        report.write("-" * 70 + "\n")
        report.write("Open Ports Identified:\n")

        if scan_results:
            for port in scan_results:
                report.write(f" - Port {port}\n")
        else:
            report.write(" No open ports detected.\n")

        # -------------------------------------------------
        # Vulnerability Findings
        # -------------------------------------------------
        report.write("\n2. VULNERABILITY FINDINGS\n")
        report.write("-" * 70 + "\n")

        if vulnerabilities:
            for v in vulnerabilities:
                report.write(
                    f"[!] Port {v['port']} | {v['attack']} "
                    f"({v['severity']})\n"
                )
                report.write(f"    Description: {v['description']}\n")
        else:
            report.write(" No vulnerabilities detected.\n")

        # -------------------------------------------------
        # Attack Correlation (Log Analysis)
        # -------------------------------------------------
        report.write("\n3. ATTACK CORRELATION RESULTS\n")
        report.write("-" * 70 + "\n")

        if detected_attacks:
            for attack in detected_attacks:
                report.write(f" - {attack}\n")
        else:
            report.write(" No attack patterns detected from logs.\n")

        # -------------------------------------------------
        # AI Security Recommendations
        # -------------------------------------------------
        report.write("\n4. AI SECURITY ANALYSIS & RECOMMENDATIONS\n")
        report.write("-" * 70 + "\n")

        if ai_response:
            report.write(ai_response + "\n")
        else:
            report.write(" AI analysis was not performed.\n")

        # -------------------------------------------------
        # Conclusion
        # -------------------------------------------------
        report.write("\n5. CONCLUSION\n")
        report.write("-" * 70 + "\n")
        report.write(
            "This assessment identified multiple security weaknesses "
            "that may pose a risk to the target environment. It is "
            "strongly recommended to prioritize remediation of "
            "CRITICAL and HIGH risk findings and implement continuous "
            "security monitoring.\n"
        )

    # File written successfully
