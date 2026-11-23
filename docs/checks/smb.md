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
nxc smb <host> --dns-server <dc_ip>
nxc smb <host> -u '' -p '' --shares --dns-server <dc_ip>
nxc smb <dc> -u '' -p '' --shares --users --dns-server <dc_ip>
nxc smb <host> -u <username> -p <password> --shares --dns-server <dc_ip>
```

The anonymous enumeration commands run only when NetExec reports a null
session. User enumeration is restricted to discovered Domain Controllers.
The share-access checks use the Standard User account and are prompted only
when needed. Configuration and share access are checked across hosts
concurrently, with four workers by default; use `--workers` to choose between
one and 16. Share access is checked once per host. Only rows with reported
READ or write-related permissions are displayed.

## What it checks

ad-kit records:

- **SMB signing** - required or not.
- **SMBv1** - enabled or not.
- **Null session** - whether NetExec reports an anonymous SMB session.
- **Anonymous enumeration** - share counts on all hosts and account counts
  on Domain Controllers, when enumeration succeeds.
- **Share access** - readable and write-related share permissions reported for
  the Standard User without writing any files. Only write-related permissions
  generate a finding.

The signing, SMBv1, and anonymous checks are unauthenticated. The
share-access checks use the Standard User account and are prompted only when
needed.

The null-session column shows **Permitted** when NetExec reports a null
session, and **Not confirmed** otherwise. The latter does not prove anonymous
access is disabled. For enumeration, **Not attempted** means NetExec did not
report a null session. **Incomplete** means the check did not produce a
complete result. Counts reflect objects
reported by NetExec, not whether the shares are readable. Partially returned
account counts are marked as incomplete.

For confirmed null sessions, the console displays one current-run sample:
up to ten anonymous user rows from a Domain Controller where available,
falling back to share rows from a controller or another host. An excerpt
without rows does not establish that enumeration was denied. Captured evidence
for other hosts remains in the evidence directory.

If a host or an individual enumeration command fails, ad-kit retains confirmed
results from other checks and hosts. The console summarises affected host
counts; individual incomplete checks are listed in the HTML report. Hosts
without any usable SMB configuration result are omitted from the configuration
tables; this does not establish whether they are offline, filtered, or otherwise
unreachable. Hosts with partially confirmed results remain visible, and the
share-access checks still attempt every discovered host.

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
- With writable shares, the Standard User can place or modify files on a share
  where write access was not intended.

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