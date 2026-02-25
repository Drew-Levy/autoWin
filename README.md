# AutoWin
### Automatically Win (dows)

Windows reconnaissance, explotation, and persistence tool to use in Penetration Testing and Red Team enagements.

> [!WARNING]
> This tool is intended for **authorized red team engagements**. Do not use this for evil.

---

## Requirements

- Python 3.9
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [Impacket](https://github.com/fortra/impacket)
- [BloodHound / BloodHound.py](https://github.com/dirkjanm/BloodHound.py)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

---

## Installation

```bash
git clone https://github.com/drew-levy/AutoWin.git
```

---

## Usage

```bash
autoWin [ip] [-u USER] [-p PASSWORD] [-EXPLOIT]
```

### Global Flags

| Flag | Description |
|---|---|
| `ip` | Target IP address |
| `protocol` | Protocol used within NetExec (optional) |
| `-d, -domain` | Target Domain Name |
| `-dc` | Domain Controller |
| `-target` | Target user/machine |
| `-u, -user` | Target username |
| `-user-list` | Path to a username wordlist |
| `-password-list` | Path to a password wordlist |
| `-p, -password` | Target password |
| `-H, -hash` | Target NTLM hash |
| `-k, -kerberos` | Use Kerberos authentication |

---

## Reconnaissance Options

| Flag | Description |
|---|---|
| `-scan` | Scan subnet for active machines with NetExec |
| `-enum` | Run enum4linux to gather system information |
| `-findusers` | Brute force valid users with Nmap |
| `-brute-user` | Attempt to brute force valid usernames |
| `-userscan` | Retrieve users via NetExec |
| `-getusers, -get-users` | Get all domain users and output to file for password spraying |
| `-passwd` | Retrieve password policy |
| `-rpc` | Attempt anonymous RPC bind; enumerate if successful |
| `-shares` | Enumerate SMB shares |
| `-ldap, -ldapsearch` | Enumerate users via LDAP |
| `-bloodhound` | Run BloodHound collection |
| `-findDelegation, -delegation` | Find delegation misconfigurations for potential abuse |
| `-mssql, -sql` | Run MSSQL enumeration and exploitation modules |
| `-extras, -e` | Run all auxiliary modules |

---

## Exploitation Methods

| Flag | Description |
|---|---|
| `-roast, -r` | Run AS-REP Roasting, Kerberoasting, and Timeroasting attacks |
| `-rbcd` | Exploit Resource-Based Constrained Delegation (RBCD) |
| `-clean` | Clean up artifacts after RBCD exploitation |
| `-adcs` | Enumerate and exploit Active Directory Certificate Services (ADCS) |
| `-esc` | Specify a specific ESC privilege escalation path (e.g., `ESC1`, `ESC4`) |
| `-gpoabuse, -gpo` | Abuse Group Policy Objects (GPO) |
| `-gpoID` | Specify the GPO ID required for GPO abuse |

---

## Persistence Options

| Flag | Description |
|---|---|
| `-skeleton` | Deploy a skeleton key attack using a custom password |
| `-dsrm` | Enable Domain Admin authentication using a stolen DSRM hash |

---

## Examples

**Enumerate users via Kerberos:**
```bash
autoWin 10.10.10.100 -d corp.local -dc 10.10.10.1 -findusers
```

**Roast Attacks:**
```bash
autoWin 10.10.10.100 -u drew -p Password123! -roast
```

**Enumerate SMB shares anonymously:**
```bash
autoWin 10.10.10.100 -shares
```

**Run BloodHound collection:**
```bash
autoWin 10.10.10.100 -d corp.local -u drew -p Password123! -bloodhound
```

**ADCS ESC1 exploitation:**
```bash
autoWin 10.10.10.100 -d corp.local -u drew -p Password123! -adcs -esc ESC1
```

**RBCD Attack and cleanup:**
```bash
autoWin 10.10.10.100 -d corp.local -u drew -p Password123! -rbcd
autoWin 10.10.10.100 -d corp.local -u drew -p Password123! -clean
```

**Skeleton Key:**
```bash
autoWin 10.10.10.100 -u drew -p Password123! -skeleton BACKDOORPASSWORD
```
**DSRM Authentication:**
```bash
autoWin 10.10.10.100 -u drew -p Password123! -dsrm
```
---

## Note

This project is still a work in progress and will receive addition updates when I find time to work on it.