import os
import subprocess
import ipaddress
import signal

SECONDS = 0

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"


def display_banner():
    # Add your banner content here
    print("""\033[91m"


	███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
	████╗  ██║████╗ ████║██╔══██╗██╔══██╗
	██╔██╗ ██║██╔████╔██║███████║██████╔╝
	██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
	██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
	╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                                                                
\u001b[0m      |  Nikto's Nmap Tool  |  For the OSCP | 2023  |  \033[1;33;0m                          
                        

    """
)

def handle_exit(signal, frame):
    print(f"\n{RED}Scan interrupted by user.")
    exit(0)

def select_scan_type():
    print(f"{YELLOW}Select the type of scan:")
    print("1. Quick Scan")
    print("2. Basic Scan")
    print("3. UDP Scan")
    print("4. Full Range Scan")
    print("5. Vulnerability Scan")
    print("6. Recon Scan")

    scan_type = None
    while scan_type not in ["1", "2", "3", "4", "5", "6"]:
        scan_type = input(">")

    if scan_type == "1":
        return "Quick"
    elif scan_type == "2":
        return "Basic"
    elif scan_type == "3":
        return "UDP"
    elif scan_type == "4":
        return "Full"
    elif scan_type == "5":
        return "Vulns"
    elif scan_type == "6":
        return "Recon"

def assign_ports(ip):
    basic_ports = ""
    if os.path.exists(f"nmap/Basic_{ip}.nmap"):
        with open(f"nmap/Basic_{ip}.nmap", "r") as file:
            basic_ports = ",".join(line.split()[0].split("/")[0] for line in file if "open" in line)

    all_ports = ""
    if os.path.exists(f"nmap/Full_{ip}.nmap"):
        with open(f"nmap/Full_{ip}.nmap", "r") as file:
            all_ports = ",".join(line.split()[0].split("/")[0] for line in file if "open" in line)

    udp_ports = ""
    if os.path.exists(f"nmap/UDP_{ip}.nmap"):
        with open(f"nmap/UDP_{ip}.nmap", "r") as file:
            udp_ports = ",".join(line.split()[0].split("/")[0] for line in file if "open" in line)
            if udp_ports == "Al":
                udp_ports = ""

    return basic_ports, all_ports, udp_ports

def check_ping(ip):
    ping_test = subprocess.run(["ping", "-c", "1", "-W", "3", ip], capture_output=True, text=True)
    if ping_test.returncode == 0:
        return "nmap"
    else:
        return ping_test.stdout

def check_os(ttl):
    os_type = ""
    if ttl <= 64:
        os_type = "Linux"
    elif ttl <= 128:
        os_type = "Windows"
    else:
        os_type = "Unknown"
    return os_type

def run_scan(ip, scan_type):
    global SECONDS
    if scan_type == "Quick":
        print(f"{YELLOW}Running Quick Scan on {ip} ({SECONDS}s elapsed)")
        subprocess.run(["nmap", "-T4", "-F", "-oN", f"nmap/Quick_{ip}.nmap", ip])
        SECONDS += 15
    elif scan_type == "Basic":
        print(f"{YELLOW}Running Basic Scan on {ip} ({SECONDS}s elapsed)")
        subprocess.run(["nmap", "-T4", "-A", "-oN", f"nmap/Basic_{ip}.nmap", ip])
        SECONDS += 30
    elif scan_type == "UDP":
        print(f"{YELLOW}Running UDP Scan on {ip} ({SECONDS}s elapsed)")
        subprocess.run(["nmap", "-sU", "-oN", f"nmap/UDP_{ip}.nmap", ip])
        SECONDS += 60
    elif scan_type == "Full":
        print(f"{YELLOW}Running Full Range Scan on {ip} ({SECONDS}s elapsed)")
        subprocess.run(["nmap", "-p-", "--min-rate", "5000", "-oN", f"nmap/Full_{ip}.nmap", ip])
        SECONDS += 600
    elif scan_type == "Vulns":
        basic_ports, all_ports, _ = assign_ports(ip)
        if basic_ports:
            print(f"{YELLOW}Running Vulns Scan on open ports of {ip} ({SECONDS}s elapsed)")
            subprocess.run(["nmap", "-p", basic_ports, "--script", "vuln", "-oN", f"nmap/Vulns_{ip}.nmap", ip])
            SECONDS += 600
        if all_ports:
            print(f"{YELLOW}Running Vulns Scan on all found ports of {ip} ({SECONDS}s elapsed)")
            subprocess.run(["nmap", "-p", all_ports, "--script", "vuln", "-oN", f"nmap/Vulns_{ip}.nmap", ip])
            SECONDS += 600
    elif scan_type == "Recon":
        print(f"{YELLOW}Suggesting Recon commands for {ip} ({SECONDS}s elapsed)")
        subprocess.run(["nmap", "-p-", "--min-rate", "5000", "-oN", f"nmap/Recon_{ip}.nmap", ip])
        SECONDS += 300
        print(f"{YELLOW}Running Thorough Scan on {ip} ({SECONDS}s elapsed)")
        subprocess.run(["nmap", "-T4", "-A", "-oN", f"nmap/Recon_{ip}.nmap", ip])
        SECONDS += 300
        print(f"{YELLOW}Running DNS Enumeration on {ip} ({SECONDS}s elapsed)")
        subprocess.run(["nmap", "-p 53", "--script", "dns-nsid", "-oN", f"nmap/Recon_{ip}.nmap", ip])
        SECONDS += 300

def main():
    global SECONDS
    display_banner()
    signal.signal(signal.SIGINT, handle_exit)

    print(f"{YELLOW}Enter target IP address or range (CIDR format):")
    target = input(">")

    scan_type = select_scan_type()
    print(f"\n{BLUE}Initiating {scan_type} Scan on {target}...\n")
    SECONDS = 0

    if "-" in target:
        ip_range = target.split("-")
        start_ip = ip_range[0].strip()
        end_ip = ip_range[1].strip()
        start_ip_split = start_ip.split(".")
        end_ip_split = end_ip.split(".")
        if len(start_ip_split) == 4 and len(end_ip_split) == 4:
            for i in range(int(start_ip_split[3]), int(end_ip_split[3]) + 1):
                ip = f"{start_ip_split[0]}.{start_ip_split[1]}.{start_ip_split[2]}.{i}"
                run_scan(ip, scan_type)
        else:
            print(f"{RED}Invalid IP range format. Exiting...")
    elif "/" in target:
        try:
            ip_network = ipaddress.IPv4Network(target, strict=False)
            for ip in ip_network:
                run_scan(str(ip), scan_type)
        except ValueError:
            print(f"{RED}Invalid IP range format. Exiting...")
    else:
        run_scan(target, scan_type)

    print(f"\n{GREEN}Scan completed in {SECONDS}s.")

if __name__ == "__main__":
    main()
