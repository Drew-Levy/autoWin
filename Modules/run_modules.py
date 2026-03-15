from colored import Fore, Style
from typing import List
import subprocess

USING_KERBEROS= False
def run_module_smb(name: str, module: str, ip: str, user: str, password: str, auth: str, *extra_args):
    """Run Netexec with SMB"""
    print(f"----- {name} -----")

    cmd = ["nxc", "smb", ip, "-M", module, "-u", user, auth, password]
    cmd.extend(extra_args)

    if USING_KERBEROS:
        cmd.append("-k")
    run_command(cmd)
    print()


def run_module_mssql(name: str, module: str, ip: str, user: str, password: str, auth: str, *extra_args):
    """Run Netexec with MSSQL"""
    print(f"----- {name} -----")

    cmd = ["nxc", "mssql", ip, "-M", module, "-u", user, auth, password]
    cmd.extend(extra_args)

    if USING_KERBEROS:
        cmd.append("-k")
    run_command(cmd)
    print()


def run_module_ldap(name: str, module: str, ip: str, user: str, password: str, auth:str,  *extra_args):
    """Run Netexec with LDAP"""
    print(f"----- {name} -----")

    cmd = ["nxc", "ldap", ip, "-M", module, "-u", user, auth, password]
    cmd.extend(extra_args)

    if USING_KERBEROS:
        cmd.append("-k")
    run_command(cmd)
    print()

def get_output(result: subprocess.CompletedProcess) -> str:
    """Extract combined stdout+stderr string from a CompletedProcess."""
    return (result.stdout or "") + (result.stderr or "")

def run_command(cmd: List[str], check: bool = False, print_output=True) -> subprocess.CompletedProcess:
    """Run a command, return CompletedProcess result"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        if print_output:
            print(result.stdout + result.stderr)
        return result 
    except subprocess.CalledProcessError as e:
        if print_output:
            print(e.stdout + e.stderr)
        return subprocess.CompletedProcess(cmd, e.returncode, e.stdout, e.stderr)
    except Exception as e:
        print(f"Error running command: {e}")
        return subprocess.CompletedProcess(cmd, 1, "", str(e))
    
def execute_powershell(target: str, username: str, password: str, domain: str, ps_command: str, use_hash: bool = False) -> tuple[bool,str]:
    cmd = ['nxc', 'smb', target, '-u', username, '-d', domain]
    if use_hash:
        cmd.extend(['-H', password])
    else:
        cmd.extend(['-p', password])
    cmd.extend(['-X', ps_command])

    try:
        result = run_command(cmd, False, False)
        output = result.stdout + result.stderr

        if '[-]' in output or 'STATUS_LOGON_FAILURE' in output or 'STATUS_ACCESS_DENIED' in output:
            return False, output

        success = '[+]' in output or 'SUCCEED' in output.upper()
        return success, output

    except Exception as e:
        return False, f"{Fore.RED}[-] Error executing command: {str(e)}"