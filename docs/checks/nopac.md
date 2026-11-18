# NoPAC Check

Tests each discovered Domain Controller for the NoPAC vulnerability chain
([`CVE-2021-42278`](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
and
[`CVE-2021-42287`](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287))
by comparing PAC and non-PAC TGT responses.

```bash
ad-kit check nopac
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec against each Domain Controller:

```bash
nxc smb <dc_ip> -u <username> -p <password> -M nopac
```

Replace `<dc_ip>`, `<username>`, and `<password>` with your Domain Controller IP
and Standard User credentials.

## What it checks

ad-kit compares the size of a TGT returned with a Privilege Attribute
Certificate (PAC) against one returned without it. A "without PAC" TGT smaller
than the "with PAC" TGT indicates the controller is vulnerable.

## How it works

NoPAC chains two issues:

- [`CVE-2021-42278`](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
  is `sAMAccountName` spoofing: an account can be renamed to match a Domain
  Controller (minus the trailing `$`).
- [`CVE-2021-42287`](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
  is a KDC lookup flaw: requesting a service ticket for a nonexistent account
  causes the KDC to append `$` and resolve the matching machine account,
  mis-associating the ticket.

The PAC carries the user's security information (SID, groups, rights). A
controller that returns a TGT without a PAC can be induced to issue tickets
that bypass normal PAC validation, enabling the `S4U2Self` flow to impersonate
a privileged user such as Administrator.

## Why it matters

A vulnerable controller can be abused to escalate a standard domain account up
to Domain Administrator. NoPAC and `sAMAccountName` spoofing are independent
conditions: a controller may be NoPAC-vulnerable while still blocking the
rename (for example with `ms-DS-MachineAccountQuota` set to zero). Patching is
the only complete fix.

## Findings

| Finding ID | Title |
|------------|-------|
| NOPAC-001 | NoPAC Vulnerability Detected |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): `-M nopac` (used by this check).
- [noPac](https://github.com/cube0x0/noPac): scanner and exploitation.

## References

- [Pentest Journeys: NoPAC](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/nopac)
- [Fortinet: from user to Domain Admin in 60 seconds](https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds)
- [MSRC: CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [MSRC: CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)