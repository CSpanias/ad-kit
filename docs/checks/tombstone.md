# Tombstone Check

Checks whether the Standard User can query deleted Active Directory objects.

```bash
ad-kit check tombstone
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec against each Domain Controller:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M tombstone -o ACTION=query
```

## What it checks

The results table includes returned `sAMAccountName` values when available;
some deleted objects may not have a name.

ad-kit retrieves objects in the Deleted Objects container with a read-only
query action. The query never restores or deletes anything.

## How it works

When objects are deleted in Active Directory, they enter a tombstone state and
remain in the Deleted Objects container until the tombstone lifetime expires.
These objects can retain directory attributes that disclose information about
the environment. Read access to the container should be limited to
administrative roles.

## Why it matters

A standard user who can read deleted objects may recover information about
former accounts, groups, and configuration that assists reconnaissance or
further attack planning.

## Findings

| Finding ID | Title |
|------------|-------|
| TOMB-001 | Deleted AD Objects Readable by Standard User |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check (`-M tombstone`).

## References

- [Microsoft: Active Directory Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin-step-by-step)
- [Microsoft: Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)