# Check Commands

Execute assessment checks and generate HTML and JSON findings with supporting 
evidence.

```bash
# Run all assessment checks in the established workflow order
ad-kit check
ad-kit check all

# Execute one or more selected assessment modules
ad-kit check ldap smb pass-pol

# Skip checks using a space-separated list at the end
ad-kit check all --exclude ldap smb
ad-kit check ldap smb --exclude ldap

# Limit concurrent target checks; 1 runs them sequentially
ad-kit check --workers 2 ldap smb
ad-kit check smb --workers 8
```

Selected modules are separated by spaces and executed in the order provided,
with one combined report. The former `check run` syntax and comma-separated
check selection are no longer supported; use `ad-kit check ldap smb` instead.
Checks requiring a Standard User account will prompt for credentials once and
reuse them across subsequent checks. Some checks (e.g., MAQ) may prompt for DA
credentials.

`--exclude` accepts the exact check names listed below, separated by spaces.
Specify it once, after selected checks and all other options. Without selected
checks, it applies to the full assessment. Comma-separated exclusions are no
longer supported.
Unknown names and excluding every selected check are errors.
`script-path` is an alias for the existing `scriptPath` check and can also be
used in selected checks and `--exclude` lists. Report filenames retain `scriptPath`.

Commands return a nonzero exit status for invalid input or a check that could
not run. Remaining checks still execute and reports are written with coverage
gaps. An incomplete observation alone does not necessarily mean a check failed
to run; review the incomplete checks in the HTML report.

Before checks start, an advisory preflight warns about known missing local tools,
session data and required inventory files. It does not test connectivity, tool
versions or credentials, and does not stop the remaining checks.
The impact summary lists selected checks and asks for confirmation when they may
create temporary objects, request roastable Kerberos material, or actively probe
NoPAC or authentication coercion. MAQ and DNS attempt cleanup, but manual
removal may be needed if cleanup fails. Declining cancels the run.

If Pre2k, NoPAC, AS-REP roasting or Kerberoasting reports Kerberos clock skew,
AD-KIT offers to set the local system clock from that DC's unauthenticated NTP
response and retry the command once. This affects other processes, needs
permission to set the clock and requires UDP port 123 to the DC. Declining,
an unavailable time source or continued skew leaves the check incomplete.

Checks show progress through known targets, groups, script paths or queries where
available. Counts represent items processed, including incomplete checks.
External commands without measurable progress display an activity indicator
instead; they may continue running between progress updates.

LDAP configuration, SMB configuration, and SMB share access use up to four
workers by default. `--workers` accepts one through 16; select a lower value
for sensitive environments. Dependent operations on each target remain
ordered, and check modules themselves still run sequentially.

MAQ and DNS display current-run command evidence after their tables. LDAP and
SMB each display one anonymous enumeration sample with up to ten result rows;
the checks still cover every target. Known passwords are redacted; review
other potentially sensitive output before sharing screenshots.

Report filenames identify the checks in the current run:

- `ad-kit/ad-kit_findings_all.html` and `.json` for a full run, including
  runs with exclusions.
- `ad-kit/ad-kit_findings_privileged.html` and `.json` for a single check.
- `ad-kit/ad-kit_findings_ldap_smb.html` and `.json` for selected checks,
  using their names in execution order. Repeated names appear once in the
  filename.

With `--csacyber`, XML is written instead of JSON using the same suffix.
The XML contains the domain item and separate items for affected hosts for
LDAP, NoPAC, coercion, SMB, and DC local-administrator findings. Only confirmed
affected hosts receive each finding. Domain-wide findings remain on the domain
item. Findings without a SureFormat mapping are omitted with a warning.

Host items group SMB findings under TCP port 445, LDAP signing and anonymous
bind findings under TCP port 389, and LDAP channel binding findings under TCP
port 636. These are standard service ports, not independently verified open
ports. Other findings, including domain-level findings, use an empty port.

DC hostname/IP pairs come from enumeration. Other hosts are resolved using the
session's DC as a DNS server. If a hostname cannot be resolved to one
unambiguous IP, it is exported by hostname with an empty IP and a warning.
Review those warnings before importing the XML. A host finding with no recorded
affected host remains on the domain item with a warning.

```bash
ad-kit check --csacyber
ad-kit check ldap nopac coercion smb --csacyber
```

The separate `--dc` switch has been removed. Each run replaces only the
matching HTML and selected export; older exports, including previously
generated `-dc.xml` files, are not removed.

When a command or host check cannot be completed, ad-kit preserves confirmed
findings and lists incomplete checks in the console and HTML report. The JSON
export contains findings only; consult the collapsed **Incomplete checks**
section at the end of the HTML report for coverage gaps.

The HTML report is self-contained and has **Copy Markdown** buttons for each 
finding and for its individual commentary, evidence, and remediation sections. 
Affected assets are included in commentary, and references in remediation. 
MAQ and DNS finding evidence is also included in the commentary copy.

Individual section copies omit their section titles; the full finding copy
includes them.

## Available Checks

| Check | Command | Description |
|-------|---------|-------------|
| LDAP | `ad-kit check ldap` | LDAP signing, channel binding, anonymous bind |
| SMB | `ad-kit check smb` | SMB signing, SMBv1, anonymous shares, DC users, readable and writable shares |
| AS-REP Roasting | `ad-kit check asreproast` | AS-REP roastable accounts + privileged membership |
| Kerberoasting | `ad-kit check kerberoast` | Kerberoastable accounts + privileged membership |
| AD CS | `ad-kit check adcs` | Certificate template/CA misconfigurations (ESC) |
| NoPAC | `ad-kit check nopac` | NoPAC vulnerability on Domain Controllers |
| DNS | `ad-kit check dns` | ADIDNS record creation permissions |
| Pre-Windows 2000 | `ad-kit check pre2k` | Pre-2000 computer account passwords |
| Script Path | `ad-kit check script-path` | User logon script path write access (`scriptPath` remains supported) |
| Privileged Groups | `ad-kit check privileged` | Privileged group membership + DCSync rights |
| Delegation | `ad-kit check delegation` | Unconstrained/constrained delegation |
| Password Policy | `ad-kit check pass-pol` | Domain password policy assessment |
| Password Not Required | `ad-kit check password-not-required` | PASSWD_NOTREQD accounts |
| Password Never Expires | `ad-kit check password-never-expires` | Non-expiring password accounts |
| Machine Account Quota | `ad-kit check maq` | Machine account creation quota |
| Tombstone | `ad-kit check tombstone` | Deleted AD object access |
| Local Administrator | `ad-kit check local-admin` | Local admin access on domain hosts |
| LDAP Info Exposure | `ad-kit check ldap-info` | Sensitive LDAP attribute exposure |
| Authentication Coercion | `ad-kit check coercion` | Coercion attack paths + Print Spooler |