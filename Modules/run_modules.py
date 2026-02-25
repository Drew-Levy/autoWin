from .utils import run_command

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