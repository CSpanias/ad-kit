# Authentication Coercion Check

Identifies Domain Controllers that expose authentication-coercion techniques
and those with the Print Spooler service enabled.

```bash
ad-kit check coercion
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated) and the Domain
    Controller hostname inventory from `ad-kit enum`.

## What it checks

ad-kit runs several NetExec modules against the Domain Controller list:

- `spooler` - whether the Print Spooler service is enabled.
- `coerce_plus` - which coercion techniques are exposed, such as PrinterBug,
  PetitPotam, DFSCoerce, and MSEven.
- `webdav` - whether the WebClient service is enabled (WebDAV coercion).

## How it works

Authentication coercion abuses legitimate Windows services and RPC interfaces
to make a Domain Controller authenticate back to a host controlled by the
attacker. Common techniques include PrinterBug (via the Print Spooler
service), PetitPotam (via MS-EFSR), DFSCoerce (via MS-DFSNM), MSEven, and
WebDAV.

Coercion by itself does not compromise the controller. Its value is the
outbound NTLM authentication it produces, which can then be relayed to a
service that accepts relayed authentication, such as a host without SMB signing
or an Active Directory Certificate Services web enrolment endpoint.

## Why it matters

A coercible Domain Controller is a source of authentication that can be turned
into impersonation of its machine account through NTLM relay. When combined
with a suitable relay target, this can lead to privilege escalation; for
example, relaying a Domain Controller machine account to an unsecured AD CS
endpoint can lead to domain compromise. Where the Print Spooler service is
enabled, the PrinterBug technique is reported and Microsoft recommends
disabling it on Domain Controllers.

## Findings

| Finding ID | Title |
|------------|-------|
| COERCE-001 | Domain Controllers Susceptible to Authentication Coercion |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [Coercer](https://github.com/p0dalirius/Coercer): coercion enumeration.
- [PetitPotam](https://github.com/topotam/PetitPotam): MS-EFSR coercion.
- [Responder](https://github.com/lgandx/Responder): name resolution poisoning.
- [Impacket](https://github.com/fortra/impacket): `ntlmrelayx`.

## References

- [mollysec: LLMNR/NBT-NS Poisoning Explained](https://mollysec.com/posts/llmr-nbt-ns-poisoning-explained/)
- [mollysec: SMB Signing and NTLM Relay Explained](https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/)
- [Pentest Journeys: NTLM Relay](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/ntlm-relay)
- [MITRE ATT&CK T1187: Forced Authentication](https://attack.mitre.org/techniques/T1187/)
- [Microsoft: NTLM overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/ntlm-overview)
- [Microsoft: print spooler service security guidance](https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)