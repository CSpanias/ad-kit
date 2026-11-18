# Password Not Required Check

Identifies enabled user accounts configured without a required password
(`PASSWD_NOTREQD`).

```bash
ad-kit check password-not-required
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec directly:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --password-not-required
```

Replace `<dc_ip>`, `<username>`, and `<password>` with your Domain Controller IP
and Standard User credentials.

## What it checks

ad-kit lists accounts with the `PASSWD_NOTREQD` flag set and reports enabled
user accounts. Machine accounts (names ending in `$`) are excluded because this
flag is expected on them and does not indicate a weak or blank password.

## How it works

The
[`PASSWD_NOTREQD`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
flag indicates that Active Directory does not require the account to have a
password. Its presence does not prove the account currently has a blank
password, but it permits the account to exist without one where the domain
configuration allows, weakening the assurance the account is protected.

## Why it matters

An account that can exist without a password is easier to compromise if the
domain configuration allows it. Reviewing flagged accounts confirms whether
the setting is still required.

## Findings

| Finding ID | Title |
|------------|-------|
| PASS-002 | Accounts Configured Without a Required Password |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check (`--password-not-required`).

## References

- [ldapwiki: PASSWD_NOTREQD](https://ldapwiki.com/wiki/Wiki.jsp?page=PASSWD_NOTREQD)
- [Microsoft: UserAccountControl attribute manipulation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Specops: find accounts using password not required](https://specopssoft.com/blog/find-ad-accounts-using-password-not-required-blank-password/)