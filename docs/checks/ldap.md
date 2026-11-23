# LDAP Check

Evaluates LDAP signing, LDAP channel binding, and anonymous bind configuration
across every discovered Domain Controller.

```bash
ad-kit check ldap
```

!!! info "Prerequisite"
    Requires the Domain Controller hostname inventory from `ad-kit enum`. The
    check itself is unauthenticated.

## Commands run

For each Domain Controller, ad-kit runs NetExec directly:

```bash
nxc ldap <controller> -u '' -p ''
nxc ldap <controller> -u '' -p '' --users
```

The user enumeration command runs when NetExec reports a successful anonymous
bind. A search failure does not prove that the bind was rejected, and an empty
result does not confirm that enumeration was denied.
The console shows current-run command evidence for successful binds, including
up to ten user rows when available.

## What it checks

ad-kit records:

- **LDAP signing** - whether the controller requires signed LDAP traffic.
- **Channel binding** - whether LDAPS authentication is bound to the TLS
  session.
- **Anonymous bind** - whether the controller accepts unauthenticated LDAP
  binds.

## How it works

LDAP is the protocol Windows systems use to query Active Directory. It runs on
the Domain Controllers, normally on:

- TCP 389 (plaintext LDAP).
- TCP 636 (LDAPS, LDAP over TLS).
- TCP 3268 and 3269 (Global Catalog).

Clients authenticate with a bind operation:

- **Simple bind** sends the credentials directly, in cleartext over plain LDAP.
- **SASL bind** authenticates with Kerberos or NTLM first and reuses that
  security context, which includes a session key.

LDAP signing uses that session key to add a cryptographic checksum to each
message so both sides can confirm its integrity and authenticity. A closely
related control, sealing, uses the same key to encrypt the message contents.
Because both require a session key, they work only with SASL binds; simple bind
is incompatible with signing.

LDAP channel binding protects the encrypted path (LDAPS). It binds a Channel
Binding Token (CBT), derived from the TLS session, to the authentication so the
controller can verify that the authentication belongs to the same TLS channel
the client established. Without it, an attacker in an Adversary-in-the-Middle
position can relay authentication captured over one TLS session and replay it
over a new one.

## Why it matters

- Without signing, LDAP traffic can be modified in transit and authentication
  requests can be relayed.
- Without channel binding, authentication intended for a secure LDAPS channel
  can be relayed to a Domain Controller.
- If anonymous directory searches are permitted, unauthenticated clients may
  enumerate objects such as users and groups. Bind acceptance alone does not
  establish that such searches are permitted.

These controls affect credential-relay exposure and directory reconnaissance.

## Findings

| Finding ID | Title |
|------------|-------|
| LDAP-001 | LDAP Signing Not Enforced |
| LDAP-002 | LDAP Channel Binding Not Enforced |
| LDAP-003 | Anonymous LDAP Bind Permitted |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [windapsearch](https://github.com/ropnop/windapsearch): LDAP enumeration.
- [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad): LDAP enumeration.
- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump): directory dump.

## References

- [mollysec: LDAP Signing and Channel Binding Explained](https://mollysec.com/posts/ldap-singing-and-channel-binding-explained/)
- [Microsoft: enable LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server)
- [Microsoft: how LDAP channel binding works](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing#how-ldap-channel-binding-works)
- [Microsoft: anonymous LDAP operations](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled)
- [Pentest Journeys: LDAP](https://x7331.gitbook.io/boxes/services/tcp/ldap-389-636)