# Script Path Check

Enumerates user logon script paths and checks whether the Standard User has
write access to those scripts.

```bash
ad-kit check scriptPath
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit reads user logon script paths with NetExec's
[get-scriptpath](https://www.netexec.wiki/ldap-protocol/get-scriptpath)
module:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M get-scriptpath
```

The resolved SMB paths are then inspected using write-capable file handles
(Impacket, in-process - no separate shell command).
If an ACL query fails, ad-kit records the incomplete check and still attempts
the write-access probe where possible.

## What it checks

ad-kit:

1. Reads the
   [`scriptPath`](https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath)
   attribute from user objects.
2. Resolves each path (relative paths are resolved against the NETLOGON share).
3. Inspects the resolved SMB paths using write-capable file handles, without
   writing any data.

## How it works

A logon script runs automatically when the associated user signs in. Scripts
are normally stored under the `SYSVOL` tree and exposed through the NETLOGON
share. If a lower-privileged user can write to a script that a higher-privileged
or targeted account runs, they can modify it to execute their own commands in
that user's context at next logon.

## Why it matters

Write access to a logon script is an opportunity to run code as the user who
executes it, which can be a step towards privilege escalation where that user
is privileged.

## Findings

| Finding ID | Title |
|------------|-------|
| SCRIPT-001 | Logon Script Writable by Standard User |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [Impacket](https://github.com/fortra/impacket): SMB inspection.

## References

- [Microsoft: scriptPath attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath)
- [Microsoft: access control lists](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
- [OffSec Blog: identifying dangerous logon scripts](https://offsec.blog/hidden-menace-how-to-identify-misconfigured-and-dangerous-logon-scripts/)
- [Semperis: GPO logon script security](https://www.semperis.com/blog/gpo-logon-script-security/)
- [Pentest Journeys: Logon Scripts](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/logon-scripts)