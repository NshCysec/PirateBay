import re
import csv
import texttable as tt
import matplotlib.pyplot as plt

log_file_paths = [
    'openssh.log',
    'Mac.log',
    'Apache.log',
    'Linux.log',
    'win.log',
    'fwrouter.log',
]


security_keywords_mitre = {

    "authentication": "T1078",
    "failed login": "T1110",
    "access denied": "T1082",
    "intrusion detected": "T1059",
    "vulnerability": "T1190",
    "firewall alert": "T1059",
    "malware detected": "T1003",
    "unauthorized access": "T1078",
    "suspicious activity": "T1107",
    "data breach": "T1192",
    "command injection": "T1059",
    "SQL injection": "T1190",
    "malicious payload": "T1064",
    "privilege escalation": "T1068",
    "brute force attack": "T1110",
    "unusual network traffic": "T1047",
    "suspicious file activity": "T1003",
    "anomaly detected": "T1059",
    "phishing attempt": "T1566",
    "rootkit detected": "T1014",
    "DDoS attack": "T1498",
    "excessive failed login attempts": "T1110",
    "unauthorized file access": "T1078",
    "account compromise": "T1078",
    "unusual system behavior": "T1059",
    "port scanning": "T1046",
    "suspicious IP address": "T1046",
    "ransomware activity": "T1486",
    "exploit attempt": "T1201",
    "sensitive data exposure": "T1120",
    

    "apache vulnerability": "T1190",
    "apache exploit": "T1190",
    "apache remote code execution": "T1210",
    "apache webshell": "T1100",
    "apache misconfiguration": "T1027",
    

    "windows vulnerability": "T1190",
    "windows exploit": "T1190",
    "windows remote code execution": "T1210",
    "windows privilege escalation": "T1055",
    "windows lateral movement": "T1028",
    

    "mac malware": "T1003",
    "mac rootkit": "T1014",
    "mac suspicious activity": "T1107",
    "mac privilege escalation": "T1068",
    

    "openssh exploit": "T1190",
    "openssh brute force": "T1110",
    "openssh unauthorized access": "T1078",
    

    "linux vulnerability": "T1190",
    "linux exploit": "T1190",
    "linux privilege escalation": "T1068",
    "linux rootkit": "T1014",
    

    "firewall configuration change": "T1027",
    "firewall threat intelligence update": "T1002",
    "router NAT pool exhaustion": "T1490",
    "router VPN tunnel termination": "T1200",
    "router suspicious MAC address": "T1049",
    "router DHCP lease renewal": "T1035",
    "router gateway failover": "T1200",
    "router SNMP configuration change": "T1035",
    "router firewall health check": "T1035",
    "router syslog server configuration": "T1035",
    "router IPv6 routing update": "T1035",
    "router firewall license renewal": "T1035",
}


all_security_issues = []

def analyze_security_issues(log_file, source):
    security_issues = []

    try:
        with open(log_file, 'r') as file:
            data = file.read()
            for keyword, technique in security_keywords_mitre.items():
                matches = re.findall(keyword, data, re.IGNORECASE)
                if matches:
                    security_issues.append((log_file, keyword, len(matches), technique, source))

        if security_issues:
            all_security_issues.extend(security_issues)
        else:
            print(f"No security issues found in the log file: {log_file}")

    except FileNotFoundError:
        print(f"Log file '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred while processing file '{log_file}': {e}")


for log_file_path in log_file_paths:
    source = log_file_path.split('.')[0]  
    analyze_security_issues(log_file_path, source)


if all_security_issues:
    tab = tt.Texttable()
    tab.header(["File", "Keyword", "Occurrences", "MITRE ATT&CK Technique", "Source"])
    for filename, keyword, count, technique, source in all_security_issues:
        tab.add_row([filename, keyword, count, technique, source])
    print("Combined Security Issues with MITRE ATT&CK Mapping:")
    print(tab.draw())


    labels = [f"{source} - {technique}" for _, _, _, technique, source in all_security_issues]
    counts = [count for _, _, count, _, _ in all_security_issues]
    x = range(len(labels))

    plt.figure(figsize=(12, 6))
    plt.bar(x, counts, color='skyblue')
    plt.xlabel("Sources - MITRE ATT&CK Technique")
    plt.ylabel("Occurrences")
    plt.xticks(x, labels, rotation=45, fontsize=8)
    plt.title("Combined Security Issues with MITRE ATT&CK Mapping")
    plt.tight_layout()
    plt.show()
else:
    print("No security issues found in the combined log files.")
def export_security_issues_to_csv(filename, data):
    with open(filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["File", "Keyword", "Occurrences", "Source"])
        csvwriter.writerows(data)

export_security_issues_to_csv('security_issues.csv', all_security_issues)
