#!/usr/bin/env python3
"""
DECEPTION-LENS v1.1
Network Truth Revealer - Sees through all illusions
Improved: Cross-platform, auto-detect subnet, better detection, error handling.
"""
import scapy.all as scapy
import netifaces
import json
from datetime import datetime
import subprocess
import sys
import os
import argparse
import ipaddress
import time

class NetworkRealityDistortion:
    def __init__(self, subnet=None):
        self.reality_log = []
        self.illusions_found = 0
        self.subnet = subnet or self._auto_detect_subnet()
        
    def _auto_detect_subnet(self):
        """Auto-detect local subnet from interfaces."""
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            gateway_ip = gateways['default'][netifaces.AF_INET][0]
            iface = gateways['default'][netifaces.AF_INET][1]
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)
        # Fallback to common subnet if detection fails
        return "192.168.1.0/24"
    
    def get_network_info(self):
        """Get basic network reality."""
        reality = {
            "timestamp": str(datetime.now()),
            "interfaces": {},
            "subnet": self.subnet,
            "illusions": []
        }
        
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                reality["interfaces"][interface] = addrs
            except Exception as e:
                reality["interfaces"][interface] = {"error": str(e)}
        
        return reality
    
    def _parse_arp_table(self):
        """Parse ARP table cross-platform."""
        real_arp = {}
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Windows: "192.168.1.1           00-11-22-33-44-55     dynamic"
                # Linux: "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
                if 'dynamic' in line.lower() or ('at' in line and '[' in line):
                    parts = line.replace('(', '').replace(')', '').replace('[', '').replace(']', '').split()
                    if len(parts) >= 4:
                        ip = parts[1] if 'at' in line else parts[0]
                        mac = parts[3] if 'at' in line else parts[1].replace('-', ':')
                        if ipaddress.ip_address(ip):
                            real_arp[ip] = mac.lower()
        except Exception as e:
            print(f"[-] Error parsing ARP table: {e}")
        return real_arp
    
    def detect_arp_illusions(self):
        """Find ARP spoofing in real-time."""
        print("[+] Scanning for ARP deceptions...")
        
        real_arp = self._parse_arp_table()
        illusions = []
        
        try:
            ans, unans = scapy.arping(self.subnet, timeout=2, verbose=0)
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc.lower()
                real_mac = real_arp.get(ip)
                if real_mac and real_mac != mac:
                    illusion = {
                        "type": "ARP_Spoofing",
                        "target_ip": ip,
                        "real_mac": real_mac,
                        "fake_mac": mac,
                        "description": f"Someone is pretending to be {ip}"
                    }
                    illusions.append(illusion)
                    self.illusions_found += 1
        except Exception as e:
            print(f"[-] Error during ARP scan: {e}")
        
        return illusions
    
    def detect_honeypots(self, ip):
        """Improved honeypot detection: Check multiple ports, response times, banners."""
        print(f"[+] Analyzing {ip} for deception...")
        
        tests = {
            "open_ports_ratio": 0,
            "response_time": float('inf'),
            "banner_truth": "",
            "suspicious_ports": []
        }
        
        unusual_ports = [13337, 31337, 9999, 12345]  # Common unusual ports
        open_count = 0
        
        for port in unusual_ports:
            try:
                start_time = time.time()
                pkt = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
                resp = scapy.sr1(pkt, timeout=1, verbose=0)
                response_time = time.time() - start_time
                if resp and resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == 18:  # SYN-ACK
                    open_count += 1
                    tests["suspicious_ports"].append(port)
                    if response_time < tests["response_time"]:
                        tests["response_time"] = response_time
            except Exception as e:
                continue
        
        tests["open_ports_ratio"] = open_count / len(unusual_ports)
        if tests["open_ports_ratio"] > 0.5:
            tests["banner_truth"] = f"Responds to {open_count}/{len(unusual_ports)} unusual ports - HIGHLY SUSPICIOUS (possible honeypot)"
        elif tests["open_ports_ratio"] > 0:
            tests["banner_truth"] = f"Responds to {open_count} unusual ports - MODERATELY SUSPICIOUS"
        else:
            tests["banner_truth"] = "No unusual port responses - Appears genuine"
        
        return tests
    
    def create_reality_map(self):
        """Generate visualization data."""
        print("\n" + "="*60)
        print("REALITY DISTORTION FIELD REPORT")
        print("="*60)
        
        reality = self.get_network_info()
        
        print("\n[REAL NETWORK STATE]")
        for iface, data in reality["interfaces"].items():
            if "error" not in data and netifaces.AF_INET in data:
                print(f"Interface {iface}: {data[netifaces.AF_INET]}")
        
        print(f"\n[SCANNING SUBNET: {self.subnet}]")
        print("\n[ILLUSIONS DETECTED]")
        arp_illusions = self.detect_arp_illusions()
        
        if arp_illusions:
            for illusion in arp_illusions:
                print(f"🚨 {illusion['type']}: {illusion['description']}")
                print(f"   Real MAC: {illusion['real_mac']}")
                print(f"   Fake MAC: {illusion['fake_mac']}")
        else:
            print("✅ No ARP spoofing detected")
        
        print("\n[HONEYPOT ANALYSIS]")
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0]
        if default_gateway:
            honeypot_test = self.detect_honeypots(default_gateway)
            if honeypot_test["open_ports_ratio"] > 0:
                print(f"⚠️  Gateway {default_gateway} shows honeypot characteristics")
                print(f"   {honeypot_test['banner_truth']}")
                print(f"   Response time: {honeypot_test['response_time']:.2f}s")
            else:
                print(f"✅ Gateway {default_gateway} appears genuine")
        else:
            print("[-] No default gateway found")
        
        print("\n" + "="*60)
        print(f"TOTAL ILLUSIONS FOUND: {self.illusions_found}")
        print("="*60)
        
        # Save to file
        report = {
            "reality_check": reality,
            "arp_illusions": arp_illusions,
            "honeypot_tests": honeypot_test if default_gateway else {},
            "summary": {
                "illusions_found": self.illusions_found,
                "timestamp": str(datetime.now()),
                "reality_score": max(0, 100 - (self.illusions_found * 20))
            }
        }
        
        with open("network_reality_report.json", "w") as f:
            json.dump(report, f, indent=4)
        
        print("\n[+] Report saved to network_reality_report.json")
        return report

def install_dependencies():
    """One-command setup."""
    print("[+] Installing reality-bending dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "scapy", "netifaces"], check=True)
        print("[+] Dependencies installed successfully!")
        return True
    except Exception as e:
        print(f"[-] Installation failed: {e}")
        print("\nManual installation:")
        print("pip install scapy netifaces")
        return False

def main():
    """Main deception revelation."""
    parser = argparse.ArgumentParser(description="DECEPTION-LENS: Network Illusion Breaker")
    parser.add_argument("--subnet", help="Subnet to scan (e.g., 192.168.1.0/24)", default=None)
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════╗
    ║        DECEPTION-LENS v1.1                   ║
    ║        Network Illusion Breaker              ║
    ║        See through all false realities       ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Check root/admin
    if os.name == 'posix' and os.geteuid() != 0:
        print("[-] Need root privileges for full reality perception")
        print("[+] Running with limited vision...")
    
    # Install if needed
    try:
        import scapy
        import netifaces
    except ImportError:
        if not install_dependencies():
            return
    
    # Create the lens
    lens = NetworkRealityDistortion(subnet=args.subnet)
    
    # Reveal the truth
    print("\n[+] Focusing the DECEPTION-LENS...")
    reality_report = lens.create_reality_map()
    
    # Final wisdom
    print("\n" + "="*60)
    print("GNOSTIC NETWORK WISDOM:")
    print("="*60)
    print("""
    1. Everything on the network can lie
    2. MAC addresses are suggestions, not laws
    3. Open ports can be traps
    4. Silence can be more truthful than response
    5. The map is not the territory
    """)
    
    score = reality_report["summary"]["reality_score"]
    if score > 80:
        print(f"📊 REALITY SCORE: {score}/100 - Your network is relatively honest")
    elif score > 50:
        print(f"📊 REALITY SCORE: {score}/100 - Some illusions present")
    else:
        print(f"📊 REALITY SCORE: {score}/100 - Network is a hall of mirrors")

if __name__ == "__main__":
    main()