# Pre-Windows 2000 Check

Identifies pre-created computer accounts that permit authentication using the
legacy pre-Windows 2000 machine-account password convention.

```bash
ad-kit check pre2k
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec directly:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M pre2k
```

## What it checks

ad-kit finds pre-created computer accounts and attempts to request a Ticket
Granting Ticket (TGT) using the default machine-account password.

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