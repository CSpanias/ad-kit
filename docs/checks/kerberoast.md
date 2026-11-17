# Kerberoasting Check

Identifies accounts with Service Principal Names (SPNs) whose Kerberos service
tickets can be requested and cracked offline — and flags any of those SPN
accounts that are also privileged.

```bash
ad-kit check kerberoast
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## What it checks

An SPN maps a Kerberos service instance to a sign-in account. Any authenticated
domain user can request a service ticket (TGS) for an SPN; that ticket is
encrypted with a key derived from the service account's password, so it can be
cracked offline — the Kerberoasting technique.

ad-kit runs Impacket `GetUserSPNs.py -request` to enumerate SPN-associated
accounts and request their hashes, then cross-references the results against
the monitored privileged groups.

## Why it matters

A weak service-account password can be recovered offline with minimal detection
risk and reused as a valid domain credential.

!!! warning "Quiet and high-impact"
    Each TGS request logs only a single `4769` event, among thousands per day,
    so Kerberoasting is easy to miss. An SPN on a privileged account can mean
    immediate, high-impact access. Machine and managed service accounts (with
    strong, automatically rotated secrets) are far less exposed than a standard
    user account holding an SPN.

See [Kerberoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/kerberoasting)
for the full attack flow and demonstrations.

## Findings

| Finding ID | Title |
|------------|-------|
| KERB-001 | Kerberoastable Accounts Identified |
| KERB-002 | Service Principal Names Assigned to Privileged Accounts |

## Tooling

- **Enumeration / request** — Impacket `GetUserSPNs.py -request`
- **Manual alternatives** — NetExec `--kerberoasting`, Rubeus `kerberoast`
- **Targeted (set-SPN)** — `targetedKerberoast.py`, NetExec `--targeted-kerberoast`
- **Cracking** — `hashcat -m 13100`, `john`

## References

- [Pentest Journeys — Kerberoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/kerberoasting)
- [Microsoft — Service accounts governance (on-premises)](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-govern-on-premises)
- [Microsoft — Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)
- [InfrasOS — Kerberoasting attack detection, prevention & mitigation](https://infrasos.com/kerberoasting-attack-detection-prevention-mitigation)