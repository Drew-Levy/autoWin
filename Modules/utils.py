import subprocess
import re
import os
import sys
from typing import List, Set
import socket
from pathlib import Path

def auth_was_successful(output: str) -> bool:
    if "[+]" in output:
        if "KRB_AP_ERR" in output:
            return False
        return True
    return False

def run_command(cmd: List[str], check: bool = False, print_output=True) -> str:
    """Run a command, return output """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        output = result.stdout + result.stderr
        if print_output:
            print(output)
        return output
    except subprocess.CalledProcessError as e:
        output = e.stdout + e.stderr
        print(output)
        return output
    except Exception as e:
        print(f"Error running command: {e}")
        return ""
    
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def check_and_fix_hosts(ip, domain) ->bool:
    try:
        resolved_ip = socket.gethostbyname(domain)
        if resolved_ip == ip:
            return True
    except socket.error:
        pass
    try:
        with open("/etc/hosts", "a") as f:
            f.write(f"\n{ip}\t{domain}\n") 
        print("[+] Successfully updated /etc/hosts")
        return True
    except Exception as e:
        print(f"[-] Failed to write to /etc/hosts: {e}")
        return False

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def get_kerberos_ticket(domain, user, password, ip) -> bool:
    check_and_fix_hosts(ip, domain)

    cmd = ["getTGT.py", f"{domain}/{user}:{password}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output=result.stdout+ result.stderr
    print(output)

    if "Saving ticket in" in output:
        match = re.search(r"Saving ticket in ([^\s]+)", output)
        if match:
            ccache_path = os.path.abspath(match.group(1))
            os.environ["KRB5CCNAME"] = ccache_path
            print(f"[+] Ticket successfully retrieved: {ccache_path}")
            print(f"[+] KRB5CCNAME environment variable set.")
            return True
        if "SessionError" in output:
            print("[-] TGT Request failed (SessionError). Check credentials.")
            return False   
    print("[-] Failed to retrieve Kerberos ticket.")
    return False

def load_wordlist(filepath: str, is_password: bool = False) -> List[str]:
    """ Load and deduplicate entries from user/password wordlist"""
    if not Path(filepath).exists():
        print(f":{'Password' if is_password else 'User'} wordlist not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    seen: Set[str] = set()
    items: List[str] = []
    empty_password_added = False
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()

            if is_password and line == "empty":
                if not empty_password_added:
                    items.append("")
                    empty_password_added= True
                continue
            
            if not line:
                continue
            if line not in seen:
                seen.add(line)
                items.append(line)
    return items

def add_users_to_file(output, user_file="users.txt"):
    #rpc and nxc formats
    patterns = [r"User:\[([^\]]+)\]",r"SMB\s+\S+\s+\d+\s+\S+\s+([a-zA-Z0-9._-]+)\s{2,}"]

    blacklist = {"-Username-"}

    existing_users = set()
    if Path(user_file).exists():
        with open(user_file, "r", encoding="utf-8", errors="ignore") as f:
            existing_users = {line.strip() for line in f if line.strip()}

    found_users = set()
    for pattern in patterns:
        found_users.update(re.findall(pattern, output))
    with open(user_file, "a", encoding="utf-8") as f:
        for user in sorted(found_users):
            if user not in existing_users and user not in blacklist:
                f.write(user + "\n")
                existing_users.add(user)

def find_user(domain: str, ip: str, user_list) -> None:
    if not domain or not user_list:
        print("[-] -findusers requires -domain and a user_list file", file=sys.stderr)
        return

    run_command(["nmap","-p", "88","--script=krb5-enum-users",f"--script-args=krb5-enum-users.realm={domain},userdb={user_list}", ip])

def get_domain(ip) -> str:
    domain = subprocess.run([f"nxc smb {ip} | awk '{{print $13}}' | sed 's/(domain://g' | sed 's/)//g'"], shell=True, capture_output=True, text=True)
    return domain.stdout.strip()