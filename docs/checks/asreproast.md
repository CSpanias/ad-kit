# AS-REP Roasting Check

Identifies user accounts configured **without Kerberos pre-authentication**
(`UF_DONT_REQUIRE_PREAUTH`), which makes them susceptible to offline password
cracking via AS-REP roasting — and flags any of those accounts that also belong
to a monitored privileged group.

```bash
ad-kit check asreproast
```

!!! info "Prerequisite"
    Requires the filtered domain user list produced by `ad-kit enum`.

## What it checks

Kerberos pre-authentication normally requires a client to prove knowledge of
its password before the KDC issues a Ticket Granting Ticket (TGT). When an
account has **"Do not require Kerberos pre-authentication"** set, an
unauthenticated client can request an AS-REP for it, and the response contains
password-derived material suitable for offline cracking.

ad-kit runs Impacket `GetNPUsers.py` in unauthenticated mode against that user
list, extracts the affected account names from the returned Hashcat-format
hashes, and then (only if matches are found) prompts for a Standard User
password to check whether any roastable account is privileged.

## Why it matters

AS-REP roasting lets an attacker obtain and crack account credentials **without
ever authenticating**. Because cracking happens offline, it generates almost no
authentication traffic and is hard to spot through account-lockout or logon
monitoring. A recovered password is a valid domain credential useful for
enumeration, lateral movement, and privilege escalation.

!!! warning "Only weak passwords crack"
    AS-REP exposure enables offline cracking, but the attack only pays off
    against weak or guessable passwords.

For attack mechanics and manual tooling, see
[AS-REPRoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/as-reproasting).

## Findings

| Finding ID | Title |
|------------|-------|
| ASREP-001 | Accounts Susceptible to AS-REP Roasting |
| ASREP-002 | Privileged Accounts Susceptible to AS-REP Roasting |

## Tooling

- **Enumeration** — Impacket `GetNPUsers.py` (`-no-pass -usersfile`)
- **Manual alternatives** — Rubeus `asreproast`, NetExec `--asreproast`, Kerbrute
- **Cracking** — `hashcat -m 18200`, `john --format=krb5asrep`

## References

- [Pentest Journeys — AS-REPRoasting](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/as-reproasting)
- [MITRE ATT&CK T1558.004 — AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [The Hacker Recipes — ASREProast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)
- [Understanding AS-REP Roasting (IT People Network)](https://itpeoplenetwork.com/blog/itsecurity/Understanding-AS-REP-Roasting-Threat-Analysis-and-Prevention-Strategies.html)