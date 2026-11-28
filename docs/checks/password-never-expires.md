# Password Never Expires Check

Identifies enabled user accounts configured with a non-expiring password
(`DONT_EXPIRE_PASSWD`).

```bash
ad-kit check password-never-expires
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec's
[password-never-expires](https://www.netexec.wiki/ldap-protocol/password-never-expires)
flag:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --password-never-expires
nxc ldap <dc_ip> -u <username> -p <password> --groups <privileged_group>
```

## What it checks

ad-kit lists accounts with the `DONT_EXPIRE_PASSWD` flag set and reports enabled
user accounts. Machine accounts (names ending in `$`) are excluded because their
secrets rotate independently of this flag. NetExec's current table filters out
disabled accounts. Unrecognized or failed output is reported as incomplete rather
than as an empty result.
When accounts are found, ad-kit queries each monitored privileged group and
shows direct memberships in an additional column and the finding evidence.
Nested membership is not established by these queries. Failed membership
lookups are reported as incomplete without discarding the account finding.

## How it works

The
[`DONT_EXPIRE_PASSWD`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
flag exempts an account's password from password-expiration policy. It does not
by itself mean the password is weak or compromised, but a password that never
expires remains valid for longer, increasing its exposure window if it is
disclosed. Service accounts may legitimately need the setting, but should use
managed credentials where practical.

## Why it matters

A non-expiring password that is disclosed or guessed remains usable
indefinitely. Reviewing these accounts confirms whether the setting is
justified.

## Findings

| Finding ID | Title |
|------------|-------|
| PASS-003 | Accounts Configured with Non-Expiring Passwords |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check (`--password-never-expires`).

## References

- [ldapwiki: DONT_EXPIRE_PASSWORD](https://ldapwiki.com/wiki/Wiki.jsp?page=DONT_EXPIRE_PASSWORD)
- [Microsoft: UserAccountControl attribute manipulation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Microsoft: Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)