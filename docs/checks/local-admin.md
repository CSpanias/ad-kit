# Local Administrator Check

Determines whether the configured Standard User has local administrator access
on any domain-joined systems, including Domain Controllers.

```bash
ad-kit check local-admin
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit first builds a host list with NetExec:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --computers
```

Then it attempts an SMB login with the Standard User against each host:

```bash
nxc smb <hosts_file> -u <username> -p <password>
```

For interactive multi-host scans, ad-kit displays NetExec's progress when
available. Otherwise, it keeps the activity spinner. NetExec controls its own
thread count; ad-kit's `--workers` does not limit this bulk scan.

## What it checks

ad-kit attempts an SMB login with the Standard User against each host and
detects success (`Pwn3d!`). Results are split into member systems and Domain
Controllers.

## How it works

Local administrator access grants control of a system: installing software,
modifying services, reading sensitive local data, and interacting with other
sessions. An account with local admin on one host can be used to harvest
credentials and move further through the environment. Administrative access to
a Domain Controller is far more significant because it provides direct access
to Active Directory data.

## Why it matters

Over-provisioned local administration is a common enabler of privilege
escalation and lateral movement. Restricting it to dedicated administrative
accounts reduces the impact of a compromised Standard User.

## Findings

| Finding ID | Title |
|------------|-------|
| LA-001 | Standard User Has Local Administrator Access |
| LA-002 | Standard User Has Administrative Access to Domain Controller |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.

## References

- [Microsoft: local accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)
- [Microsoft: privileged access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- [Microsoft: securing Domain Controllers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
- [MITRE ATT&CK TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)