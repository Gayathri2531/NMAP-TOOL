#!/usr/bin/env python3

import nmap
import re

# Regular expressions for input validation
ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile(r"^(\d+)-(\d+)$")

print("\n****************************************************************")

print(r"""
 GGGGG    AAAAA   Y     Y   AAAAA   TTTTTTT  H     H  RRRRRR    IIIIII  
G     G  A     A   Y   Y   A     A     T     H     H  R     R     I    
G        AAAAAAA    Y Y    AAAAAAA     T     HHHHHHH  RRRRRR      I    
G  GGG   A     A     Y     A     A     T     H     H  R   R       I    
G     G  A     A     Y     A     A     T     H     H  R    R      I    
 GGGGG   A     A     Y     A     A     T     H     H  R     R   IIIIII 
""")

print("\n****************************************************************")
print("\n* Copyright of GayathriNalluri, 2025                           *")
print("\n* Author By: Gayathri Nalluri                                  *")
print("\n* GitHub: https://github.com/Gayathri2531                      *")
print("\n****************************************************************")

print("NMAP NETWORK SCANNER TOOL")

# Get target IP
while True:
    target = input("Enter target IP address: ").strip()
    if ip_pattern.fullmatch(target):
        break
    print("Invalid IP format. Try again.")

# Get port range
while True:
    port_range = input("Enter port range (e.g. 25-100): ").replace(" ", "")
    match = port_range_pattern.match(port_range)
    if match:
        port_min = int(match.group(1))
        port_max = int(match.group(2))
        if 0 <= port_min <= port_max <= 65535:
            break
    print("Invalid port range. Try again.")

# Scan types
scan_types = []
if input("Enable TCP SYN scan? (yes/no): ").strip().lower() == "yes":
    scan_types.append(("TCP SYN Scan", "-sS", "tcp"))
if input("Enable TCP Connect scan? (yes/no): ").strip().lower() == "yes":
    scan_types.append(("TCP Connect Scan", "-sT", "tcp"))
if input("Enable UDP scan? (yes/no): ").strip().lower() == "yes":
    scan_types.append(("UDP Scan", "-sU", "udp"))

# Optional info
enable_version = input("Show SERVICE VERSION info? (yes/no): ").strip().lower() == "yes"
enable_os = input("Show OPERATING SYSTEM info? (yes/no): ").strip().lower() == "yes"
enable_connection = input("Show CONNECTION TYPE used? (yes/no): ").strip().lower() == "yes"
print("\n****************************************************************")

# Initialize scanner
scanner = nmap.PortScanner()

# Perform scans
for name, args, proto in scan_types:
    scan_args = f"{args} -T4 -Pn"
    if enable_version:
        scan_args += " -sV"
    if enable_os:
        scan_args += " -O"

    print(f"\nPerforming: {name}")
        scanner.scan(hosts=target, ports=f"{port_min}-{port_max}", arguments=scan_args)

    if target not in scanner.all_hosts():
        print(f"Host {target} is OFFLINE or not responding.")
        continue

    print(f"Host {target} is ONLINE")
    print("\n****************************************************************")

    if enable_connection:
        print("\nCONNECTION TYPE")
        print(f"- Scan Method Used: {name}")
        print("\n****************************************************************")
    print("\nOPEN PORTS")
    open_ports = False
    if proto in scanner[target]:
        for port, data in scanner[target][proto].items():
            if data['state'] == 'open':
                print(f"- Port {port}/{proto.upper()} is OPEN")
                open_ports = True
    if not open_ports:
        print("No open ports found in given range.")
        print("\n****************************************************************")


    if enable_version and proto in scanner[target]:
        print("\nSERVICE VERSION INFO")
        for port, data in scanner[target][proto].items():
            if data['state'] == 'open':
                name = data.get('name', '')
                product = data.get('product', '')
                version = data.get('version', '')
                extra = data.get('extrainfo', '')
                print(f"- Port {port}: {name} {product} {version} {extra}".strip())
                print("\n****************************************************************")

    if enable_os and 'osmatch' in scanner[target]:
        print("\nOPERATING SYSTEM INFO")
        print("\n****************************************************************")

        for osmatch in scanner[target]['osmatch'][:3]:
            print(f"- {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
            print("\n****************************************************************")
# Specific port check
if input("\nDo you want to check a specific port? (yes/no): ").strip().lower() == "yes":
    while True:
        try:
            specific_port = int(input("Enter the specific port number (0-65535): "))
            if 0 <= specific_port <= 65535:
                break
            print("Port must be between 0 and 65535.")
        except ValueError:
            print("Please enter a valid number.")

    proto_choice = input("Check with TCP or UDP? (tcp/udp): ").strip().lower()
    if proto_choice not in ['tcp', 'udp']:
        proto_choice = 'tcp'

    scan_flag = "-sS" if proto_choice == 'tcp' else "-sU"
    scanner.scan(hosts=target, ports=str(specific_port), arguments=f"{scan_flag} -T4 -Pn")
    print("\n****************************************************************")
    print("\nSPECIFIC PORT CHECK")
    try:
        port_state = scanner[target][proto_choice][specific_port]['state']
        print(f"- Port {specific_port}/{proto_choice.upper()} is {port_state.upper()}")
    except:
        print("Could not determine status (port may be filtered or unreachable).")

# Final message
print("\n****************************************************************")
print("         THANK YOU FOR USING THIS TOOL – HAPPY SCANNING!        ")
print("****************************************************************")


