# Delegation Check

Reviews Active Directory Kerberos delegation configuration and flags accounts
configured with unconstrained delegation or constrained delegation with
protocol transition, including any that are privileged.

```bash
ad-kit check delegation
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec against the Domain Controller:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --find-delegation
```

The `--find-delegation` flag corresponds to NetExec's
[find misconfigured delegation](https://www.netexec.wiki/ldap-protocol/find-misconfigured-delegation).
Use an up-to-date NetExec version: older versions may omit unconstrained
delegation when an account also has constrained delegation configured.

## What it checks

ad-kit finds enabled accounts configured with unconstrained delegation and
accounts with constrained delegation and protocol transition
(`--find-delegation`). Disabled accounts are not included. It excludes Domain
Controller machine accounts and the Azure AD Kerberos trust object, then flags
delegated accounts that are also members of a monitored privileged group.
The results table lists affected accounts alongside each delegation count.

## How it works

Kerberos delegation lets a service request tickets on behalf of a user:

- **Unconstrained delegation** is the legacy mechanism. When a user
  authenticates to the delegated service, their Ticket Granting Ticket (TGT)
  is cached on the host and can be reused to request further tickets for that
  user. If the host is compromised, those cached TGTs can be extracted.
- **Constrained delegation** limits which services the account can impersonate
  users to. **Protocol transition** (`S4U2Self`) lets the account first obtain
  a ticket for a user who has not yet authenticated to it, and then request
  services on their behalf.

## Why it matters

Compromising a delegated account or its host can allow impersonation of the
users who authenticate to it. Where a privileged user, or the delegated
account itself, is privileged, this provides a path to privilege escalation
and wider compromise. The preferred alternative is Resource-Based Constrained
Delegation, or migrating to Group Managed Service Accounts.

## Findings

| Finding ID | Title |
|------------|-------|
| DELEG-001 | Unconstrained Delegation Enabled |
| DELEG-002 | Kerberos Constrained Delegation with Protocol Transition Enabled |
| DELEG-003 | Delegation Configured on Privileged Accounts |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [Impacket](https://github.com/fortra/impacket): Kerberos tooling.
- [krbrelayx](https://github.com/dirkjanm/krbrelayx): delegation abuse.

## References

- [Microsoft: Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft: service accounts governance](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-govern-on-premises)
- [Dirk-jan Mollema: unconstrained delegation abuse](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
- [James Forshaw: exploiting RBCD](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)