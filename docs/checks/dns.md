# DNS Check

Checks whether authenticated users can create records within Active
Directory-integrated DNS (ADIDNS) zones.

```bash
ad-kit check dns
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated) and
    [bloodyAD](https://github.com/CravateRouge/bloodyAD) installed.

## Commands run

ad-kit uses bloodyAD to add, then remove, a temporary `dnsRecord`:

```bash
bloodyAD -u <username> -p <password> -d <domain> --dc-ip <dc_ip> add dnsRecord <name> <ip>
bloodyAD -u <username> -p <password> -d <domain> --dc-ip <dc_ip> remove dnsRecord <name> <ip>
```

The [`add dnsRecord`](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide#add-dnsrecord) and [`remove dnsRecord`](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide#remove-dnsrecord) commands come from the bloodyAD User Guide.

## What it checks

ad-kit verifies whether a standard domain user can modify DNS data by adding a
temporary `dnsRecord` entry and attempting to remove it. If removal cannot be
confirmed, it warns with the record name and creation evidence path. It may
prompt for Domain Administrator credentials to retry cleanup; otherwise, check
whether the record remains and remove it.

## How it works

Active Directory-integrated DNS zones are stored in the AD database and
replicated between Domain Controllers. In a secure configuration, only
authorised principals can create or modify records. If an authenticated user
can add arbitrary records, they can register names that redirect traffic,
impersonate a service, or support further attacks.

## Why it matters

DNS names are widely trusted by domain systems, so the ability to create or
modify records can be leveraged for traffic redirection, spoofed services such
as WPAD, or availability disruption.

## Findings

| Finding ID | Title |
|------------|-------|
| DNS-001 | Authenticated Users Can Create DNS Records |

## Tooling

- [bloodyAD](https://github.com/CravateRouge/bloodyAD): used by this check.
- [krbrelayx](https://github.com/dirkjanm/krbrelayx): `dnstool.py` for ADIDNS records.
- [dnsrecon](https://github.com/darkoperator/dnsrecon): DNS enumeration.

## References

- [Microsoft: configure DNS dynamic updates](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-dns-dynamic-updates-windows-server-2003)
- [Microsoft: DNS and Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/dns-and-ad-ds)
- [Netwrix: DNS in Active Directory](https://blog.netwrix.com/2017/02/17/dns-in-active-directory/)
- [Pentest Journeys: DNS](https://x7331.gitbook.io/boxes/services/tcp/dns-53)
- [Pentest Journeys: DnsAdmins](https://x7331.gitbook.io/boxes/tl-dr/active-directory/groups/dnsadmins)