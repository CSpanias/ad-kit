# SMB Check

Evaluates SMB signing, SMBv1, anonymous access, and Standard User read and
write-related access to shares across discovered systems.

```bash
ad-kit check smb
```

!!! info "Prerequisite"
    Requires the Domain Controller and domain computer inventories from
    `ad-kit enum`. The share-access checks use a Standard User account.

## Commands run

ad-kit runs NetExec against the discovered hosts:

```bash
nxc smb <host> -u '' -p '' --dns-server <dc_ip>
nxc smb <host> -u '' -p '' --shares --dns-server <dc_ip>
nxc smb <dc> -u '' -p '' --shares --users --dns-server <dc_ip>
nxc smb <host> -u <username> -p <password> --shares --dns-server <dc_ip>
```

The anonymous enumeration commands run when the empty-credential login
succeeds, including when it is mapped to a Guest session. User enumeration is
restricted to discovered Domain Controllers.
The share-access checks use the Standard User account and are prompted only
when needed. SMB configuration is checked on Domain Controllers first, and
their results are displayed before the remaining hosts are checked. Each batch
and the subsequent share-access checks use up to four workers by default; use
`--workers` to choose between one and 16. Share access is checked once per
host. The console groups shares by host and reported permissions, omitting
read-only `IPC$` and `print$` entries. Writable entries for these shares remain
visible. Full command output remains in the evidence directory, and the
omission does not affect findings.

## What it checks

ad-kit records:

- **SMB signing** - required or not.
- **SMBv1** - enabled or not.
- **Empty-credential enumeration** - whether share or user enumeration was
  verified after an anonymous or Guest-mapped SMB session.
- **Anonymous enumeration** - share counts on all hosts and account counts
  on Domain Controllers, when enumeration succeeds.
- **Share access** - readable and write-related share permissions reported for
  the Standard User without writing any files. Only write-related permissions
  generate a finding. Its evidence table groups shares by host and reported
  permissions; write-related permissions alone do not prove direct file-write
  access.

The signing, SMBv1, and anonymous checks are unauthenticated. The
share-access checks use the Standard User account and are prompted only when
needed.

The host configuration table summarises signing, SMBv1, and anonymous
enumeration counts in one row each. Unknown counts include hosts without usable
results. A separate Guest column appears when enumeration succeeds through a
Guest-mapped session.

Both tables report anonymous enumeration as **Enabled** when share names or
users are observed, **Guest** when those results are obtained through a
Guest-mapped session, and **Disabled** when empty-credential authentication is
denied or all attempted enumerations complete without returning objects.
Inconclusive results are **Unknown**. User enumeration is attempted only on
DCs. The DC table includes share and user count columns only when the
corresponding objects are observed on at least one DC. This status describes
enumeration results, not whether a null session was established.
The SMB signing and SMBv1 findings summarise the number of affected systems,
including the number of Domain Controllers where applicable, rather than
listing each host. Raw per-host command output remains in the evidence
directory.
Incomplete checks are also recorded in the HTML report. Enumeration counts
reflect objects reported by NetExec, not whether shares are readable.
Partially returned account counts are marked as incomplete.
The anonymous-enumeration finding describes share names, user account
information, or both according to the objects actually observed across hosts.
It notes that enumeration does not prove access to share contents only when
share names were observed. Its commentary summarises the number of affected
systems and distinguishes null and Guest-mapped sessions. Its affected-assets
and evidence sections are omitted from the report; raw per-host command output
remains in the evidence directory.

For confirmed anonymous-enumeration findings, the console displays one current-run sample:
up to ten anonymous user rows from a Domain Controller where available,
falling back to share rows from a controller or another host. An excerpt
without rows does not establish that enumeration was denied. Captured evidence
for other hosts remains in the evidence directory.

If a host or an individual enumeration command fails, ad-kit retains confirmed
results from other checks and hosts. The console summarises affected host
counts beside the relevant configuration or share-access results; individual
incomplete checks are listed in the HTML report. Domain
Controllers without usable SMB configuration results are omitted from the DC
table. Their absence does not establish whether they are offline, filtered,
or otherwise unreachable. The share-access checks still attempt every
discovered host.

## How it works

SMB is the Windows file-sharing and remote-administration protocol, reachable
on ports 139 and 445. SMB signing adds a keyed hash to each SMB message,
derived from a session key established during authentication. Each side uses
this hash to confirm that a message came from a peer holding the same key and
was not modified in transit.

Because NTLM provides no mutual authentication, an attacker positioned between
a client and a server can forward the authentication exchange (relay). If the
target does not require SMB signing, the relayed session can be used. If
signing is required, the attacker cannot produce valid signatures without the
session key, so the relayed session cannot be used.

SMBv1 is the legacy version of the protocol and lacks the protections of SMBv2
and SMBv3. It has been tied to several long-standing vulnerabilities and
should be disabled.

## Why it matters

- Without signing, SMB authentication can be relayed and messages can be
  modified.
- With SMBv1 enabled, hosts expose legacy functionality with known weaknesses.
- With anonymous access, share names and account lists can be enumerated
  without credentials.
- Where effective file-write access is available, unintended file placement or
  modification may enable NTLM authentication capture and relay attacks.

## Findings

| Finding ID | Title |
|------------|-------|
| SMB-001 | SMB Signing Not Enforced |
| SMB-002 | SMBv1 Enabled |
| SMB-003 | Anonymous SMB Enumeration Permitted |
| SMB-004 | SMB Shares Writable by Standard User |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [Impacket](https://github.com/fortra/impacket): SMB and RPC tooling.
- [smbmap](https://github.com/ShawnDEvans/smbmap): share enumeration and access.
- [smbclient](https://www.samba.org/): SMB client for share interaction.
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng): enumeration.

## References

- [mollysec: SMB Signing and NTLM Relay Explained](https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/)
- [Microsoft: SMB signing overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Microsoft: detect, enable, and disable SMBv1](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Pentest Journeys: SMB](https://x7331.gitbook.io/boxes/services/tcp/shares/smb-139-445)
- [Pentest Journeys: NTLM relay](https://x7331.gitbook.io/boxes/tl-dr/active-directory/attacks/ntlm-relay)