# Kerberoasting Check

Identifies accounts with Service Principal Names (SPNs) whose Kerberos service
tickets can be requested and cracked offline, and flags any of those accounts
that are also privileged.

```bash
ad-kit check kerberoast
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs Impacket
[`GetUserSPNs.py -request`](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py):

```bash
GetUserSPNs.py <domain>/<username>:<password> -dc-ip <dc_ip> -request -outputfile <outfile>
```

## What it checks

ad-kit enumerates SPN-associated accounts and requests their Kerberos service
tickets, then cross-references the results against the monitored privileged
groups.
The results table lists the affected account names alongside the count.

## How it works

An SPN maps a Kerberos service instance to a sign-in account. Any authenticated
domain user can request a service ticket (TGS) for an SPN, and the ticket is
encrypted with a key derived from the service account's password, so it can be
cracked offline.

Modern environments often attach services to machine accounts or managed
service accounts, whose strong secrets rotate automatically and are hard to
crack. The risk is higher where a standard user account holds one or more SPNs,
because that password's strength and rotation depend on manual management.

## Why it matters

A weak service-account password can be recovered offline and reused as a valid
domain credential. When the SPN is on a privileged account, recovery can give
immediate, high-impact access.

See
[Kerberoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/kerberoasting)
for the full attack flow.

## Findings

| Finding ID | Title |
|------------|-------|
| KERB-001 | Kerberoastable Accounts Identified |
| KERB-002 | Service Principal Names Assigned to Privileged Accounts |

## Tooling

- [Impacket](https://github.com/fortra/impacket): `GetUserSPNs.py -request` (used by this check).
- [NetExec](https://github.com/Pennyw0rth/NetExec): `--kerberoasting`.
- [Rubeus](https://github.com/GhostPack/Rubeus): `kerberoast`.
- [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast): set-SPN variant.
- [hashcat](https://github.com/hashcat/hashcat): `hashcat -m 13100`.

## References

- [Pentest Journeys: Kerberoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/kerberoasting)
- [Microsoft: service accounts governance](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-govern-on-premises)
- [Microsoft: Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)
- [InfrasOS: Kerberoasting detection, prevention and mitigation](https://infrasos.com/kerberoasting-attack-detection-prevention-mitigation)