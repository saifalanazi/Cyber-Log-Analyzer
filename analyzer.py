import re
import csv
import os

# Main logic to parse SSH logs and identify brute-force patterns
def analyze_ssh_logs(log_file, output_csv):
    failed_attempts = {}
    print(f"[*] Scanning log file: {os.path.basename(log_file)}")

    try:
        with open(log_file, 'r', encoding='utf-8') as file:
            for line in file:
                # Detection logic: search for "Failed password" strings
                if "Failed password" in line:
                    # Use Regex to isolate the source IP address
                    ip_search = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                    if ip_search:
                        ip = ip_search.group()
                        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                            
    except FileNotFoundError:
        print(f"[-] Error: Target log file not found at {log_file}")
        return

    # Filter and categorize IPs exceeding the threat threshold (3 attempts)
    attackers = []
    for ip, count in failed_attempts.items():
        if count >= 3:
            attackers.append([ip, count, "Brute-Force Attack"])

    # Output findings to a CSV for Incident Response documentation
    if attackers:
        print(f"[!] Security Alert: Detected {len(attackers)} suspicious IP addresses.")
        with open(output_csv, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["IP Address", "Failed Attempts", "Alert Type"]) 
            writer.writerows(attackers)
        print(f"[+] Success: Security report generated at {output_csv}")
    else:
        print("[+] System health check: No threats detected.")

# Helper to create dummy data for testing purposes
def create_dummy_logs(file_name):
    if not os.path.exists(file_name):
        sample_logs = (
            "Jan 10 12:05:23 server sshd: Failed password for admin from 10.0.0.5\n"
            "Jan 10 12:05:25 server sshd: Failed password for admin from 10.0.0.5\n"
            "Jan 10 12:05:28 server sshd: Failed password for admin from 10.0.0.5\n"
            "Jan 10 12:05:30 server sshd: Failed password for admin from 10.0.0.5\n"
        )
        with open(file_name, "w", encoding='utf-8') as f:
            f.write(sample_logs.strip())

if __name__ == "__main__":
    # Ensure file operations are relative to the script's location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, "server_logs.txt")
    report_path = os.path.join(script_dir, "security_report.csv")
    
    create_dummy_logs(log_path)
    analyze_ssh_logs(log_path, report_path)