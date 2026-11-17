# AS-REP Roasting Check

Identifies user accounts configured without Kerberos pre-authentication. Such
accounts are susceptible to AS-REP roasting, which allows an unauthenticated
attacker to request encrypted material that can be cracked offline to recover
the account password.

```bash
ad-kit check asreproast
```

!!! info "Prerequisite"
    Requires the filtered domain user list produced by `ad-kit enum`.

## What it checks

ad-kit scans the domain user list for accounts with the
[`UF_DONT_REQUIRE_PREAUTH`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
flag set (the "Do not require Kerberos pre-authentication" option).

It runs Impacket's
[`GetNPUsers.py`](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
in unauthenticated mode against that list (using `-no-pass` and `-usersfile`),
extracts the affected account names from the returned AS-REP hashes, and, when
a Standard User password is available, checks whether any affected account
belongs to a monitored privileged group.

## How it works

Kerberos pre-authentication normally requires a client to prove knowledge of
the account password before the Key Distribution Centre (KDC) issues a Ticket
Granting Ticket (TGT). The client encrypts a timestamp with a key derived from
the password and sends it with the authentication request (AS-REQ). If the KDC
can decrypt and validate the timestamp, it knows the client holds the password.

When "Do not require Kerberos pre-authentication" is enabled, the KDC skips
this step. Any client with network access to the KDC can then request an AS-REP
for that account, and the response contains material encrypted with a key
derived from the account password. The attacker cracks this offline.

The requested AS-REP contains two parts:

- A Ticket Granting Ticket (TGT), encrypted with the KDC's secret key.
- A session key, encrypted with the account's secret. This is the part AS-REP
  roasting targets.

Accounts usually end up roastable because a legacy or third-party application
required pre-authentication to be disabled. An attacker with
[`GenericAll`](https://x7331.gitbook.io/boxes/tl-dr/active-directory/permissions/genericall)
or
[`GenericWrite`](https://x7331.gitbook.io/boxes/tl-dr/active-directory/permissions/genericwrite)
over an account can also set the flag deliberately, which is known as targeted
AS-REP roasting. ad-kit identifies the resulting roastable accounts but does
not currently enumerate those write rights.

## AS-REP via ARP spoofing

There is also a network-level variant that captures AS-REP material for
accounts that authenticate normally, without any directory modification.

When a user signs in to a domain-joined workstation, the client sends an AS-REQ
and the DC responds with an AS-REP. On a local network, the Address Resolution
Protocol (ARP) maps IP addresses to MAC addresses and provides no
authentication. An attacker on the same VLAN can send forged ARP responses to
impersonate the client or the DC, placing themselves between the two and
intercepting Kerberos traffic (TCP/88).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) automates this and
offers two modes:

- **Relay mode**: intercepts AS-REQ messages and forwards them to the DC,
  attempting to force RC4 where supported to simplify cracking.
- **Listen mode**: poisons the gateway's ARP cache to capture AS-REP responses
  passively.

!!! note "Not checked by ad-kit"
    ad-kit does not perform ARP spoofing or capture AS-REP traffic. This
    section is provided for reference.

```bash
# Relay mode
ASRepCatcher relay -dc 192.168.1.100

# Listen mode
ASRepCatcher listen
```

## Why it matters

AS-REP roasting provides an unauthenticated route to password material. If a
weak or guessable password is recovered, the attacker gains a valid domain
credential that can be used for further access. Impact is greatest when the
affected account also holds privileged group membership (see ASREP-002).

## Findings

| Finding ID | Title |
|------------|-------|
| ASREP-001 | Accounts Susceptible to AS-REP Roasting |
| ASREP-002 | Privileged Accounts Susceptible to AS-REP Roasting |

## Tooling

- [`GetNPUsers.py`](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) (Impacket): used by this check.
- [NetExec](https://github.com/Pennyw0rth/NetExec): `nxc ldap <dc> -u users.txt -p '' --asreproast <outfile>`.
- [Rubeus](https://github.com/GhostPack/Rubeus): `Rubeus.exe asreproast /format:hashcat`.
- [Kerbrute](https://github.com/ropnop/kerbrute): user enumeration.
- [hashcat](https://github.com/hashcat/hashcat): `hashcat -m 18200`.
- [John the Ripper](https://github.com/openwall/john): `john --format=krb5asrep`.

## References

- [MITRE ATT&CK T1558.004: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [The Hacker Recipes: ASREProast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)
- [Microsoft: UserAccountControl attribute manipulation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Pentest Journeys: AS-REPRoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/as-reproasting)