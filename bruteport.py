import argparse
import socket
import ipaddress
import concurrent.futures
import sys
import time
import random
import json
import struct
import subprocess
import platform
import re
import urllib.request
from datetime import datetime

# --- Configuration & Constants ---

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

PRESETS = {
    'web': [80, 443, 8080, 8443, 8000, 8008],
    'db': [3306, 5432, 1433, 6379, 27017, 5984, 1521],
    'ftp': [20, 21, 69, 990],
    'mail': [25, 110, 143, 465, 587, 993, 995],
    'common': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5900, 8080],
    'top100': list(range(1, 101)),
    'all': list(range(1, 65536))
}

USER_AGENTS = [
    # Chrome (Windows, Mac, Linux, Android)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    
    # Firefox (Windows, Mac, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    
    # Safari (Mac, iPhone)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    
    # Opera (Windows, Mac)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0"
]

WAF_SIGNATURES = [
    "403 Forbidden",
    "Access Denied",
    "Cloudflare",
    "WAF",
    "Firewall",
    "Block",
    "Captcha",
    "Security",
    "Denied",
    "Imperva",
    "Incapsula"
]

# --- Proxy Support (Generic SOCKS5) ---

class Socks5Proxy:
    def __init__(self, proxy_host, proxy_port):
        self.proxy_host = proxy_host
        self.proxy_port = int(proxy_port)

    def connect(self, target_host, target_port, timeout=5.0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((self.proxy_host, self.proxy_port))
            # 1. Auth Negotiation
            s.send(b'\x05\x01\x00')
            auth_resp = s.recv(2)
            if not auth_resp or auth_resp[0] != 5 or auth_resp[1] != 0:
                s.close()
                return None
            # 2. Connection Request
            host_bytes = target_host.encode('utf-8')
            req = b'\x05\x01\x00\x03' + struct.pack('B', len(host_bytes)) + host_bytes + struct.pack('>H', target_port)
            s.send(req)
            # 3. Response
            resp = s.recv(4)
            if not resp or resp[1] != 0:
                s.close()
                return None
            if resp[3] == 1: s.recv(4 + 2)
            elif resp[3] == 3: s.recv(s.recv(1)[0] + 2)
            elif resp[3] == 4: s.recv(16 + 2)
            return s
        except Exception:
            s.close()
            return None

# --- Core Functions ---

def print_banner():
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print(r"""
  ____             _ZX              _   
 |  _ \           | |              | |  
 | |_) |_ __ _   _| |_ ___ _ __ ___| |_ 
 |  _ <| '__| | | | __/ _ \ '_ \ __| __|
 | |_) | |  | |_| | ||  __/ |_) |/ | |_ 
 |____/|_|   \__,_|\__\___| .__/_\__\__|
                          | |           
                          |_|           
    """)
    print(f"       v1.6 - Advanced Python Port Scanner{Colors.ENDC}\n")

def get_os_ttl(target_ip):
    """
    Estimates OS based on TTL from ping.
    Linux ~64, Windows ~128
    """
    try:
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", "1000", target_ip]
            regex = r"TTL=(\d+)"
        else:
            ping_cmd = ["ping", "-c", "1", "-W", "1", target_ip]
            regex = r"ttl=(\d+)"
            
        output = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT).decode()
        match = re.search(regex, output, re.IGNORECASE)
        
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                return f"Linux/Unix (TTL={ttl})"
            elif ttl <= 128:
                return f"Windows (TTL={ttl})"
            else:
                return f"Unknown/Network Device (TTL={ttl})"
    except:
        pass
    return None

def get_geoip(target_ip):
    """
    Retrieves GeoIP info using ip-api.com
    """
    try:
        # Don't lookup private IPs
        if ipaddress.ip_address(target_ip).is_private:
            return "Local Network"
            
        url = f"http://ip-api.com/json/{target_ip}?fields=country,city,isp"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data and 'country' in data:
                return f"{data['country']}, {data['city']} ({data['isp']})"
    except:
        pass
    return None

def run_nmap(target_ip, ports):
    """
    Runs Nmap against the found ports.
    """
    if not ports:
        return
    
    port_list = ",".join([str(p[0]) for p in ports])
    print(f"\n{Colors.WARNING}[*] Launching Nmap for deep scan on ports: {port_list}...{Colors.ENDC}")
    
    cmd = ["nmap", "-sC", "-sV", "-p", port_list, target_ip]
    try:
        subprocess.call(cmd)
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] Nmap not found. Make sure it is installed and in your PATH.{Colors.ENDC}")

def grab_banner(sock, ip, timeout=1.5):
    try:
        sock.settimeout(timeout)
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner: return banner
        except socket.timeout: pass 
        
        try:
            random_ua = random.choice(USER_AGENTS)
            probe = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {random_ua}\r\n\r\n"
            sock.send(probe.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "Server:" in response:
                for line in response.split('\n'):
                    if "Server:" in line: return line.split("Server:", 1)[1].strip()
            if response:
                first_line = response.split('\n')[0].strip()
                if first_line: return first_line
        except: pass
        
        try:
            sock.send(b"HELP\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if response: return response
        except: pass
        return None
    except: return None

def scan_port(ip, port, detect_version=False, timeout=0.8, stealth=False, proxy=None):
    if stealth: time.sleep(random.uniform(0.1, 0.4))
    s = None
    try:
        if proxy:
            s = proxy.connect(ip, port, timeout=timeout)
            if s is None: return None
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result != 0:
                s.close()
                return None
        try: service = socket.getservbyport(port, "tcp")
        except: service = "unknown"
        version = ""
        if detect_version:
            banner = grab_banner(s, ip, timeout=timeout + 0.5)
            if banner: version = banner[:50].strip()
        s.close()
        return (port, service, version)
    except Exception:
        if s: s.close()
        return None

def update_progress(current, total, bar_length=40):
    percent = float(current) * 100 / total
    arrow = '#' * int(percent / 100 * bar_length - 1)
    spaces = '.' * (bar_length - len(arrow))
    sys.stdout.write(f"\r{Colors.BLUE}[{arrow}{spaces}] {int(percent)}%{Colors.ENDC}")
    sys.stdout.flush()

def scan_target(target_ip, ports, threads=100, detect_version=False, timeout=0.8, stealth=False, proxy=None):
    print(f"{Colors.BOLD}Scanning Target: {Colors.CYAN}{target_ip}{Colors.ENDC}")
    
    # Intelligence Checks
    if not proxy: 
        os_guess = get_os_ttl(target_ip)
        if os_guess:
            print(f"{Colors.WARNING}[*] OS Guess: {os_guess}{Colors.ENDC}")
        
        geo_info = get_geoip(target_ip)
        if geo_info:
            print(f"{Colors.WARNING}[*] Location: {geo_info}{Colors.ENDC}")

    if proxy:
        print(f"{Colors.WARNING}[Proxy Active] {proxy.proxy_host}:{proxy.proxy_port}{Colors.ENDC}")
    
    print(f"Scanning {len(ports)} ports...")
    if stealth:
        print(f"{Colors.WARNING}[!] Stealth Mode Active{Colors.ENDC}")
        ports = list(ports)
        random.shuffle(ports)
    
    open_ports = []
    total_ports = len(ports)
    completed_ports = 0
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    try:
        future_to_port = {executor.submit(scan_port, target_ip, port, detect_version, timeout, stealth, proxy): port for port in ports}
        update_progress(0, total_ports)
        for future in concurrent.futures.as_completed(future_to_port):
            completed_ports += 1
            if not stealth or (completed_ports % 5 == 0 or completed_ports == total_ports):
                update_progress(completed_ports, total_ports)
            result = future.result()
            if result:
                port, service, version = result
                version_info = f" | {Colors.WARNING}Version: {version}{Colors.ENDC}" if version else ""
                
                # Check for WAF
                waf_msg = ""
                if version:
                    for sig in WAF_SIGNATURES:
                        if sig.lower() in version.lower():
                            waf_msg = f" {Colors.FAIL}[!] ATTACK BLOCKED BY WAF!{Colors.ENDC}"
                            break
                
                sys.stdout.write(f"\r{Colors.GREEN}[+] Port {port:<5} Open - Service: {service:<10}{Colors.ENDC}{version_info}{waf_msg}" + " " * 10 + "\n")
                open_ports.append(result)
        print()
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally: executor.shutdown(wait=True)
    if not open_ports: print(f"{Colors.WARNING}No open ports found on {target_ip}.{Colors.ENDC}")
    else: print(f"\n{Colors.GREEN}Scan Completed. Found {len(open_ports)} open ports.{Colors.ENDC}")
    return open_ports

def save_report(results, filename):
    if filename.endswith('.json'):
        with open(filename, 'w') as f: json.dump(results, f, indent=4)
        print(f"{Colors.CYAN}[+] Report saved to {filename}{Colors.ENDC}")
    elif filename.endswith('.html'):
        html_content = f"""<html><head><title>Bruteport Report</title><style>body{{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:20px;}}h1{{color:#9cdcfe;}}.target{{margin-top:20px;border:1px solid #444;padding:10px;}}.port{{color:#6a9955;margin-left:20px;}}.service{{color:#569cd6;}}.version{{color:#dcdcaa;}}</style></head><body><h1>Bruteport Report</h1><p>Date: {datetime.now()}</p>"""
        for ip, ports in results.items():
            html_content += f'<div class="target"><h3>{ip}</h3>'
            if not ports: html_content += '<div class="port">No open ports.</div>'
            for p in ports: html_content += f'<div class="port">[+] {p[0]} <span class="service">{p[1]}</span> <span class="version">{p[2]}</span></div>'
            html_content += '</div>'
        html_content += "</body></html>"
        with open(filename, 'w') as f: f.write(html_content)
        print(f"{Colors.CYAN}[+] Report saved to {filename}{Colors.ENDC}")

def resolve_target(target_input):
    try: ipaddress.ip_address(target_input); return target_input
    except ValueError:
        try: return socket.gethostbyname(target_input)
        except: return None

def main():
    if sys.platform == 'win32':
        import os
        os.system('color')
    print_banner()
    parser = argparse.ArgumentParser(description="Bruteport - Advanced Python Port Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("target", nargs='?', help="Target IP or CIDR")
    group.add_argument("-iL", "--input-list", help="Target list file")
    parser.add_argument("-m", "--max-port", type=int, default=65535, help="Max port")
    parser.add_argument("-p", "--preset", type=str, choices=PRESETS.keys(), help="Port preset")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Thread count")
    parser.add_argument("-sV", "--version", action="store_true", help="Detect version")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode")
    parser.add_argument("--proxy", help="SOCKS5 Proxy (host:port)")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--nmap", action="store_true", help="Run Nmap on found ports")
    
    try: args = parser.parse_args()
    except SystemExit: raise

    targets = []
    if args.input_list:
        try:
            with open(args.input_list, 'r') as f: targets = [line.strip() for line in f if line.strip()]
            print(f"{Colors.BLUE}[*] Loaded {len(targets)} targets{Colors.ENDC}")
        except FileNotFoundError: sys.exit(1)
    elif args.target:
        if '/' in args.target:
            try: targets = [str(ip) for ip in ipaddress.ip_network(args.target, strict=False).hosts()]
            except ValueError: sys.exit(1)
        else: targets = [args.target]

    proxy = None
    if args.proxy:
        try: phost, pport = args.proxy.split(':'); proxy = Socks5Proxy(phost, pport); print(f"{Colors.WARNING}[*] Proxy Enabled{Colors.ENDC}")
        except: sys.exit(1)

    ports_to_scan = PRESETS[args.preset] if args.preset else range(1, args.max_port + 1)
    if args.stealth:
        if args.threads > 20: args.threads = 20
        if args.timeout < 1.0: args.timeout = 1.5

    all_results = {}
    try:
        for raw_target in targets:
            final_ip = resolve_target(raw_target)
            if not final_ip: continue
            
            open_ports = scan_target(final_ip, ports_to_scan, args.threads, args.version, args.timeout, args.stealth, proxy)
            all_results[raw_target] = open_ports
            
            # --- Nmap Integration ---
            if args.nmap and open_ports and not proxy:
                 run_nmap(final_ip, open_ports)
            
            print("-" * 50)
            
        if args.output: save_report(all_results, args.output)
    except KeyboardInterrupt: sys.exit(0)
    except Exception as e: print(f"{e}"); sys.exit(1)

if __name__ == "__main__":
    main()
