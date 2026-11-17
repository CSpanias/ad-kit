# NoPAC Check

Tests each discovered Domain Controller for the NoPAC vulnerability chain
(`CVE-2021-42278` / `CVE-2021-42287`) by comparing PAC and non-PAC TGT
responses.

```bash
ad-kit check nopac
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## What it checks

NoPAC chains two issues:

- `CVE-2021-42278` — `sAMAccountName` spoofing: an account can be renamed to
  match a Domain Controller (minus the trailing `$`).
- `CVE-2021-42287` — a KDC lookup flaw: requesting a service ticket for a
  nonexistent account causes the KDC to append `$` and resolve the matching
  machine account, mis-associating the ticket.

The check runs the NetExec `nopac` module against each DC and compares the size
of a TGT returned **with** a PAC against one returned **without** it. A
"without PAC" TGT smaller than the "with PAC" TGT indicates the DC is
vulnerable.

## Why it matters

A vulnerable DC can be induced to issue tickets that bypass normal PAC
authorization checks, enabling privilege escalation up to Domain Administrator
via the `S4U2Self` flow.

!!! warning "Two independent conditions"
    NoPAC and `sAMAccountName` spoofing are independent: a DC may be
    NoPAC-vulnerable while still blocking the rename (for example with
    `ms-DS-MachineAccountQuota` set to zero). Patching is the only complete fix
    — see References.

See [NoPAC](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/nopac)
for the full attack chain and manual tooling.

## Findings

| Finding ID | Title |
|------------|-------|
| NOPAC-001 | NoPAC Vulnerability Detected |

## Tooling

- **Detection** — NetExec `nxc smb <dc> -M nopac`
- **Manual alternatives** — `noPac.py` scanner, `noPac.exe scan`

## References

- [Pentest Journeys — NoPAC](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/nopac)
- [Fortinet — CVE-2021-42278 / CVE-2021-42287: from user to Domain Admin in 60 seconds](https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds)
- [MSRC — CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [MSRC — CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)