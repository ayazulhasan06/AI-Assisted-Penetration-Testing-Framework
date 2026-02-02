# =========================================
# SecureProbe - Main Controller
# Advanced AI-Assisted Penetration Testing
# =========================================

import scan_network
import vulnerability_detection
import attack_filter
import chatgpt_advisor
import report_generator
import logging
import time
from datetime import datetime

# -------------------------------------------------
# Logging Configuration
# -------------------------------------------------
logging.basicConfig(
    filename="secureprobe.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# -------------------------------------------------
# Banner & Disclaimer
# -------------------------------------------------
def display_banner():
    print("""
=====================================================
 SECUREPROBE – AI INTEGRATED PENETRATION TEST TOOL
 Advanced AI-Assisted Penetration Testing Framework
=====================================================
    """)

def display_disclaimer():
    print("""
[!] LEGAL & ETHICAL DISCLAIMER
-----------------------------------------------------
This tool is intended for AUTHORIZED security testing
ONLY. Unauthorized scanning or testing of systems
without explicit permission is illegal.
The user is solely responsible for compliance.
-----------------------------------------------------
    """)

# -------------------------------------------------
# Utility Functions
# -------------------------------------------------
def print_section(title):
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

# -------------------------------------------------
# Main Program
# -------------------------------------------------
def main():
    display_banner()
    display_disclaimer()

    logging.info("SecureProbe started")

    target_ip = input("Enter target IP or range: ").strip()
    start_time = datetime.now()

    logging.info(f"Target set to {target_ip}")

    scan_results = []
    vulnerabilities = []
    detected_attacks = []
    ai_response = ""

    while True:
        print_section("MAIN MENU")
        print("[1] Network Scan")
        print("[2] Vulnerability Detection")
        print("[3] Attack Filtering (Log Analysis)")
        print("[4] AI Security Advisor")
        print("[5] Generate Security Report")
        print("[6] Auto Run (Scan → Detect → AI → Report)")
        print("[7] Exit")

        choice = input("\nChoose option: ").strip()

        # -------------------------------------------------
        # Network Scan
        # -------------------------------------------------
        if choice == "1":
            print_section("NETWORK SCAN")
            scan_results = scan_network.scan(target_ip)
            logging.info("Network scan completed")

        # -------------------------------------------------
        # Vulnerability Detection
        # -------------------------------------------------
        elif choice == "2":
            if not scan_results:
                print("[-] Please perform a network scan first.")
                continue

            print_section("VULNERABILITY DETECTION")
            vulnerabilities = vulnerability_detection.detect_vulnerabilities(scan_results)

            if vulnerabilities:
                for v in vulnerabilities:
                    print(f"[!] Port {v['port']} - {v['attack']} ({v['severity']})")
            else:
                print("[+] No vulnerabilities detected.")

            logging.info("Vulnerability detection completed")

        # -------------------------------------------------
        # Attack Filtering
        # -------------------------------------------------
        elif choice == "3":
            print_section("ATTACK FILTERING")
            detected_attacks = attack_filter.filter_attacks("secureprobe.log")

            if detected_attacks:
                for attack in detected_attacks:
                    print(f"[!] {attack}")
            else:
                print("[+] No attack patterns detected.")

            logging.info("Attack filtering completed")

        # -------------------------------------------------
        # AI Advisor
        # -------------------------------------------------
        elif choice == "4":
            if not vulnerabilities:
                print("[-] No vulnerabilities to analyze.")
                continue

            print_section("AI SECURITY ADVISOR")
            ai_response = chatgpt_advisor.get_advice(vulnerabilities)
            print(ai_response)

            logging.info("AI advisor consulted")

        # -------------------------------------------------
        # Report Generation
        # -------------------------------------------------
        elif choice == "5":
            print_section("REPORT GENERATION")
            report_generator.generate(
                scan_results,
                vulnerabilities,
                detected_attacks,
                ai_response
            )
            print("[+] Report generated: secureprobe_report.txt")
            logging.info("Report generated")

        # -------------------------------------------------
        # AUTO MODE (NEW FEATURE)
        # -------------------------------------------------
        elif choice == "6":
            print_section("AUTO MODE EXECUTION")
            scan_results = scan_network.scan(target_ip)
            vulnerabilities = vulnerability_detection.detect_vulnerabilities(scan_results)
            detected_attacks = attack_filter.filter_attacks("secureprobe.log")
            ai_response = chatgpt_advisor.get_advice(vulnerabilities)

            report_generator.generate(
                scan_results,
                vulnerabilities,
                detected_attacks,
                ai_response
            )

            print("[+] Auto run completed successfully.")
            logging.info("Auto mode completed")

        # -------------------------------------------------
        # Exit
        # -------------------------------------------------
        elif choice == "7":
            print_section("EXIT")
            elapsed = datetime.now() - start_time
            print(f"Session Duration: {elapsed}")
            logging.info("SecureProbe exited")
            break

        else:
            print("[-] Invalid option. Please try again.")

        time.sleep(1)

# -------------------------------------------------
# Entry Point
# -------------------------------------------------
if __name__ == "__main__":
    main()
