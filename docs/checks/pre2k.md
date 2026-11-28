# Pre-Windows 2000 Check

Identifies pre-created computer accounts that permit authentication using the
legacy pre-Windows 2000 machine-account password convention.

```bash
ad-kit check pre2k
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec's [pre2k](https://www.netexec.wiki/ldap-protocol/pre2k)
module:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M pre2k
```

## What it checks

The console lists identified pre-created accounts and their individual TGT
acquisition results when NetExec reports them. An unknown result means the
account's ticket outcome could not be determined from the command output.

ad-kit finds pre-created computer accounts and attempts to request a Ticket
Granting Ticket (TGT) using the default machine-account password.
For each account with a confirmed TGT, it requests a fresh TGT in memory and
uses that ticket to attempt a Kerberos LDAP bind to the same Domain Controller.
LDAP validation failures are recorded as incomplete; they do not erase a
successful NetExec TGT result. The console displays the NetExec command and
selected results, followed by the in-process validation steps. Full NetExec
output is saved in `ad-kit/evidence/pre2k.txt`, and validation results in
`ad-kit/evidence/pre2k-ldap-validation.txt`. These results do not explicitly
print the derived password or ticket contents.

## How it works

When a computer account is created with the "Assign this computer account as a
pre-Windows 2000 computer" option, the account password is derived
predictably: the `sAMAccountName` is taken, the trailing `$` is removed, and
the first 14 characters are lowercased to form the password.

This sizeable, predictable password can be used to request a Kerberos TGT, so
an attacker can authenticate as the computer account without any prior access.

## Why it matters

A pre-created computer account provides an unauthenticated route to valid
domain authentication through predictable machine-account credentials.

## Findings

| Finding ID | Title |
|------------|-------|
| PRE2K-001 | Pre-Windows 2000 Computer Account Credentials Permit Authentication |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check (`-M pre2k`).

## References

- [TrustedSec: diving into pre-created computer accounts](https://trustedsec.com/blog/diving-into-pre-created-computer-accounts)
- [Microsoft: UserAccountControl attribute manipulation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Pentest Journeys: Pre-Created Machines](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/pre-created-machines)