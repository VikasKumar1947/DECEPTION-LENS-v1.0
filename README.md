Description:
DECEPTION-LENS v1.0 is an open-source Python-based network security tool designed to "see through illusions" in local networks. It acts as a defensive scanner that detects common deceptions like ARP spoofing (man-in-the-middle attacks) and potential honeypots (decoy systems). By analyzing network interfaces, ARP tables, and port responses, it generates a "reality distortion field report" with a score indicating network trustworthiness. The tool emphasizes education and awareness, themed around uncovering hidden threats in a dramatic, user-friendly way.

Key Features:

ARP Spoofing Detection: Compares the system's ARP cache with live network scans to identify MAC address mismatches.
Honeypot Analysis: Probes unusual ports on target devices (e.g., gateways) for suspicious behavior like excessive open ports or fast responses.
Network Mapping: Retrieves and displays interface details, gateways, and subnet information.
Reporting: Outputs results to the console and saves a detailed JSON report for further analysis.
Dependency Management: Includes automatic installation of required libraries (Scapy and netifaces).
Privilege Awareness: Checks for root/admin privileges and warns if limited.
Use Cases:

Network administrators monitoring for intrusions.
Security enthusiasts learning about ARP poisoning and honeypot detection.
Ethical hackers performing defensive assessments (with permission).
Requirements:

Python 3.x
Libraries: Scapy, netifaces (auto-installed if missing)
Elevated privileges (root on Linux/macOS, admin on Windows) for full functionality.
Limitations:

Assumes a 192.168.1.0/24 subnet by default (can be improved for dynamic detection).
Basic honeypot checks; not foolproof against advanced setups.
Cross-platform support is limited in v1.0 (improved in v1.1).
Ethical Note: Use only on networks you own or have explicit permission to scan. Unauthorized use may violate laws or policies.









output       
╔══════════════════════════════════════════════╗
║        DECEPTION-LENS v1.1                   ║
║        Network Illusion Breaker              ║
║        See through all false realities       ║
╚══════════════════════════════════════════════╝

[+] Focusing the DECEPTION-LENS...

============================================================
REALITY DISTORTION FIELD REPORT
============================================================

[REAL NETWORK STATE]
Interface eth0: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0', 'broadcast': '192.168.1.255'}]
Interface lo: [{'addr': '127.0.0.1', 'netmask': '255.0.0.0'}]

[ILLUSIONS DETECTED]
INFO: [+] Scanning for ARP deceptions...
✅ No ARP spoofing detected

[HONEYPOT ANALYSIS]
INFO: [+] Analyzing 192.168.1.1 for honeypot characteristics...
✅ Target 192.168.1.1 appears genuine

============================================================
TOTAL ILLUSIONS FOUND: 0
============================================================

INFO: [+] Report saved to 20231015_143022_network_reality_report.json

============================================================
GNOSTIC NETWORK WISDOM:
============================================================

1. Everything on the network can lie
2. MAC addresses are suggestions, not laws
3. Open ports can be traps
4. Silence can be more truthful than response
5. The map is not the territory

📊 REALITY SCORE: 100/100 - Your network is relatively honest
