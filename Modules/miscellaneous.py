from colored import Fore
import subprocess
from ..Modules.utils import add_users_to_file
from ..Modules.utils import run_command
from typing import Optional

def is_authenticated(user: str, password: str) -> None:
    return user and password
        
def get_users(protocol: str, ip: str, user: Optional[str] = None, password: Optional[str] = None, output: Optional[bool] = False)-> None:
    if user and password:
        find_users = run_command(["nxc", "smb", ip, "-u", user, "-p", password, "--users"], False, output)  
    else:
        find_users = run_command(["nxc", "smb", ip, "--users"], False, output)
    add_users_to_file(find_users)
    if output:
        print(f"{Fore.green}[+] Wrote Users to users.txt")

def list_users(protocol: str, ip: str, user: Optional[str] = None, password: Optional[str] = None) -> list:
    if user and password:
        find_users = run_command(["nxc", "smb", ip, "-u", user, "-p", password, "--users"], False)  
    else:
        find_users = run_command(["nxc", "smb", ip, "--users"], False)
    return find_users

def default_scan(protocol: str, ip: str) -> None:
    run_command(["nxc", protocol, ip])

def get_password_pol(protocol: str, ip: str, user: Optional[str] = None, password: Optional[str] = None) -> None:
    if user and password:
        run_command(["nxc", "-u", user, "-p", "password", protocol, ip, "--pass-pol"])
    else:
        run_command(["nxc", protocol, ip, "--pass-pol"])

def get_shares(protocol: str, ip: str, user: Optional[str] = None, password: Optional[str] = None) -> None:
    if user and password:
        run_command(["nxc", "smb", ip,  "-u", user, "-p", password, "--shares"])
    else:
        run_command(["nxc", "smb", ip,  "-u", "andygu", "-p", "", "--shares"])

def enum_linux(ip: str, user: Optional[str] = None, password: Optional[str] = None) -> None:
    print(f"{Fore.yellow}[*] This might take a moment...")
    if user and password:
        subprocess.run(["enum4linux", ip, "-u", user, password ])
    else:
        subprocess.run(["enum4linux", ip])

def bloodhound(ip: str, domain:str, user: str, password: str) -> None:
    run_command(["bloodhound-ce-python", "--zip", "-c", "All", "-d", domain, "-u", user, "-p", password, "-ns", ip])
    print(f"{Fore.blue}[*] Use this for cyphers: https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/")

def find_users(domain: str, ip: str, user_list: list) -> None:
    output = run_command(["nmap","-p", "88","--script=krb5-enum-users",f"--script-args=krb5-enum-users.realm={domain},userdb={user_list}", ip])
    add_users_to_file(output)
    print(f"{Fore.green}[+] Wrote Users to users.txt")
