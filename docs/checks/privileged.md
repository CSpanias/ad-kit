# Privileged Groups Check

Reviews privileged group membership, built-in account status, and DCSync
replication rights.

```bash
ad-kit check privileged
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated), NetExec, and bloodyAD.

## Commands run

ad-kit runs NetExec against the Domain Controller:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --users
nxc ldap <dc_ip> -u <username> -p <password> --admin-count
nxc ldap <dc_ip> -u <username> -p <password> --get-sid
bloodyAD -u <username> -p <password> -d <domain> --dc-ip <dc_ip> get object <domain_sid-rid> --attr sAMAccountName
nxc ldap <dc_ip> -u <username> -p <password> -M whoami -o USER=<resolved_name>
```

The `--users` flag corresponds to NetExec's
[enumerate domain users](https://www.netexec.wiki/ldap-protocol/enumerate-users)
module, and `--admin-count` to
[admin count](https://www.netexec.wiki/ldap-protocol/admin-count).

Privileged group membership and the domain DACL are read in-process using Impacket ([`get_privileged_group_members`](https://github.com/CSpanias/ad-kit/blob/main/src/ad_kit/core/privileged.py#L31) and [`dacledit.py`](https://github.com/fortra/impacket/blob/master/examples/dacledit.py)).

## What it checks

The console shows counts, percentages, and assessments for each group and the
`adminCount=1` indicator. `adminCount=1` can be stale and does not by itself
confirm current privileged access.

ad-kit:

- Compares membership of high-privilege groups against the number of enabled
  users (flagged above 10%).
- Counts accounts marked with `adminCount=1` (flagged above 25%).
- Resolves the built-in Guest and Administrator accounts by domain SID and RID
  before checking their state, including when they have been renamed. Failed
  lookups are reported as incomplete rather than treated as disabled.
- Reads the domain DACL with
  [`dacledit.py`](https://github.com/fortra/impacket/blob/master/examples/dacledit.py)
  to find non-default principals with DCSync-related replication rights.

Previously saved expected trustee SIDs remain excluded for resolved trustees
other than `Cisco_Connector`; the check no longer prompts for selections.
Rerunning `ad-kit enum` creates a new session and resets those saved selections.
Unresolved trustees with both core rights are counted in the console and
retained in the finding with their SIDs, even if they were previously selected.
An unresolved SID does not necessarily indicate a deleted account.

Trustees named `MSOL_*` are automatically excluded. Microsoft Entra Connect
express setup creates an `MSOL_`-prefixed AD DS Connector account, and password
hash synchronisation requires both core replication rights. A name prefix
alone does not verify an account's purpose; review the raw DACL evidence when
that assumption is uncertain.

Only trustees with both core rights are included in the table or finding.
Partial rights remain in the raw DACL evidence. Cisco's AD Connector requires
Replicating Directory Changes but not Replicating Directory Changes All; an
account such as `Cisco_Connector` is reported if it has both core rights.
This is not an effective-permissions calculation: permissions can also be
inherited or combined through group membership, so hiding partial trustees can
miss effective access.

## How it works

- **Group membership** proportional to the domain indicates that privileged
  access is distributed more broadly than intended.
- **`adminCount=1`** marks accounts protected by privileged groups, but can
  remain set after membership is removed, so it flags accounts needing review.
- **Built-in Guest and Administrator** are well-known, high-value identities
  that should be controlled carefully.
- **DCSync rights** (Replicating Directory Changes and Replicating Directory
  Changes All) let the holder replicate directory data including credential
  material.

## Why it matters

These indicators together surface accounts and rights that could give an
attacker administrative control, directory data, or credential material.

## Findings

| Finding ID | Title |
|------------|-------|
| PRIV-001 | Excessive Membership of Privileged Active Directory Groups |
| PRIV-002 | Large Population of Accounts Marked as Protected |
| PRIV-003 | Built-in Guest Account Enabled |
| PRIV-004 | Built-in Administrator Account Enabled |
| PRIV-005 | Unexpected DCSync-Related Replication Rights |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [Impacket](https://github.com/fortra/impacket): `dacledit.py`.

## References

- [Microsoft: avoiding excessive privileges](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory#avoid-granting-excessive-privileges)
- [NIST SP 800-53 AC-6: least privilege](https://nist-sp-800-53-r5.bsafes.com/docs/3-1-access-control/ac-6-least-privilege/)
- [Microsoft: adminCount attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-admincount)
- [Microsoft: default user accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts)
- [Altered Security: a primer on DCSync](https://www.alteredsecurity.com/post/a-primer-on-dcsync-attack-and-detection)