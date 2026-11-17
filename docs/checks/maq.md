# Machine Account Quota Check

Retrieves the domain Machine Account Quota (MAQ) and tests whether an
authenticated user can create, authenticate with, and delete a machine account.

```bash
ad-kit check maq
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## What it checks

ad-kit:

1. Reads the [`ms-DS-MachineAccountQuota`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain)
   value and the group permitted to join machines.
2. If the quota is greater than zero, attempts to create a test machine account
   with `nxc smb ... -M add-computer`.
3. Authenticates as the machine account, then deletes it and records the
   cleanup method.

## How it works

By default Active Directory allows any authenticated user to create up to 10
computer accounts. This simplifies workstation provisioning but is often
unnecessary in mature environments. A non-zero quota grants machine-account
creation domain-wide, which can be combined with Resource-Based Constrained
Delegation or other Kerberos techniques to extend a foothold.

## Why it matters

Machine-account creation is a building block for several escalation paths and
represents a deviation from least privilege when left at its default.

## Findings

| Finding ID | Title |
|------------|-------|
| MAQ-001 | Machine Account Quota Permits Machine Creation |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.

## References

- [NetSPI: MachineAccountQuota is useful sometimes](https://www.netspi.com/blog/technical-blog/network-pentesting/machineaccountquota-is-useful-sometimes/)
- [Microsoft: default workstation joins](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain)
- [PacketLabs: the overlooked danger of Machine Account Quota](https://www.packetlabs.net/posts/the-overlooked-danger-how-ms-ds-machine-account-quota-fuels-ad-attacks/)