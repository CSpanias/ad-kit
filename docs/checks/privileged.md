# Privileged Groups Check

Reviews privileged group membership, built-in account status, and DCSync
replication rights.

```bash
ad-kit check privileged
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec and Impacket against the Domain Controller:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --users
nxc ldap <dc_ip> -u <username> -p <password> --admin-count
```

Privileged group membership and the domain DACL are read in-process using
Impacket (`get_privileged_group_members` and `dacledit.py`). Replace
`<dc_ip>`, `<username>`, and `<password>` with your Domain Controller IP and
Standard User credentials.

## What it checks

ad-kit:

- Compares membership of high-privilege groups against the number of enabled
  users (flagged above 10%).
- Counts accounts marked with `adminCount=1` (flagged above 25%).
- Checks the state of the built-in Guest and Administrator accounts.
- Reads the domain DACL with
  [`dacledit.py`](https://github.com/fortra/impacket/blob/master/examples/dacledit.py)
  to find non-default principals with DCSync-related replication rights.

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