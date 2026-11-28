# Machine Account Quota Check

Retrieves the domain Machine Account Quota (MAQ) and tests whether an
authenticated user can create, authenticate with, and delete a machine account.

```bash
ad-kit check maq
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs NetExec's
[maq](https://www.netexec.wiki/ldap-protocol/machine-account-quota) module:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M maq
```

If the Machine Account Quota is greater than zero, ad-kit attempts to create a
test machine account using NetExec's `add-computer` module:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M add-computer -o NAME=<name> PASSWORD=<password>
```

It then authenticates as the machine account over SMB:

```bash
nxc smb <dc_ip> -u <name>$ -p <password>
```

And removes the test machine account using NetExec's `add-computer` module with
`DELETE=True`:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M add-computer -o NAME=<name> PASSWORD=<password> DELETE=True
```

## What it checks

ad-kit:

1. Reads the [`ms-DS-MachineAccountQuota`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain)
   value and the group permitted to join machines.
2. If the quota is greater than zero, attempts to create a test machine account.
3. Authenticates as the machine account, then deletes it and records the
   cleanup method.

If cleanup cannot be confirmed, ad-kit warns with the machine account name and
the creation evidence path. It may prompt for Domain Administrator credentials
to retry cleanup over LDAP; otherwise, check whether the account remains and
remove it.
If the Standard User cannot remove the test account, ad-kit asks whether to
retry with Domain Administrator credentials. Declining continues the assessment
and reports that manual cleanup is required.

When a finding is generated, the console shows the redacted commands and output
from the current check, including attempted cleanup, without repeating any
state-changing commands. Evidence files are retained regardless.

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