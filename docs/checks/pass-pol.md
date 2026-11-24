# Password Policy Check

Retrieves the domain password and account-lockout policy and assesses each
setting against the ad-kit baseline.

```bash
ad-kit check pass-pol
```

!!! info "Prerequisite"
    Requires a valid Standard User account. Fine-grained policy assessment is
    optional and prompts for Domain Administrator credentials.

## Commands run

ad-kit reads the default domain policy with NetExec:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --pass-pol
```

If the optional fine-grained policy assessment is selected, ad-kit also runs:

```bash
nxc ldap <dc_ip> -u <admin> -p <password> --pso
```

Its output is saved in `ad-kit/evidence/password-policy-fine-grained.txt`.
If NetExec does not provide a verifiable policy count, or the query fails,
the assessment is recorded as incomplete rather than assuming no policies exist.
NetExec rounds down fine-grained policy ages to days and lockout intervals to
minutes. A reported zero-minute lockout duration is therefore unknown when
lockout is enabled; it is not assumed to require manual unlocking.

When NetExec reports the lockout duration as `Not Set`, ad-kit also queries:

```bash
nxc ldap <dc_ip> -u <username> -p <password> --query '(objectClass=domainDNS)' 'lockoutDuration'
```

## What it checks

ad-kit reads the default domain policy and compares each setting against the
baseline:

| Setting | Baseline |
|---------|----------|
| Minimum password length | at least 12 characters |
| Password history | at least 2 remembered passwords |
| Minimum password age | at least 1 day |
| Password complexity | enabled |
| Lockout threshold | 1 to 10 attempts |
| Lockout duration | at least 30 minutes |
| Observation window | at least 15 minutes |

Settings that cannot be parsed are shown as **Unknown** and are not treated as
either compliant or weak. They are also listed as incomplete in the report.
Check `ad-kit/evidence/password-policy.txt` for the raw output.

An account lockout threshold of zero disables lockout; the duration and
observation window are then not applicable. A lockout duration of zero means
manual administrator unlock, rather than a short automatic unlock period.
NetExec may also render an indefinite duration as `Not Set`. When this occurs,
ad-kit queries the raw LDAP attribute and reports **Until manually unlocked**
if the documented manual-unlock value is returned. If the query fails or its
result is unexpected, the duration is **Unknown** and the check is incomplete.
The query output is saved in `ad-kit/evidence/password-policy-lockout-duration.txt`.
When the threshold is zero, lockout is disabled and the query is unnecessary.
Maximum password age is not assessed or displayed. NetExec's unmodified command
output, including any maximum-age value it reports, remains in the evidence file.

The finding's commentary, recommendations, and references are selected for
the settings below the ad-kit baseline; compliant or unknown settings do not
produce recommendations. Review the baseline and each finding in the context
of the organisation's requirements and other password controls.

## How it works

The password and account-lockout policy controls how resistant the domain is to
password guessing:

- **Minimum length, history, and complexity** make passwords harder to guess
  and to recycle.
- **Minimum age** prevents a user cycling passwords immediately to defeat
  password history.
- **Lockout threshold** is the number of failed attempts that lock an account.
  A value of zero disables lockout entirely and permits unlimited guessing.
- **Lockout duration** is how long a locked account remains unavailable.
- **Observation window** is the period after which the failed-attempt count is
  reset.

These settings interact, so ad-kit assesses them together. For example, a very
high lockout threshold gives an attacker many attempts, and a short observation
window means those attempts are forgotten quickly.

Fine-Grained Password Policies (Password Settings Objects) can override the
default policy for specific users and groups, so the effective policy for an
individual account may differ from the default domain policy that this check
reads. When requested, ad-kit assesses the reported policies against the same
baseline and displays each policy's settings, assessments, reported assignments,
and precedence in a separate table. Relevant settings and assignments are also
included in the finding. The fine-grained assessment flags reversible password encryption.
An assignment to a broad group does not prove that the policy applies
to every user: direct assignments, group membership and precedence affect the
resultant policy. The finding identifies default-policy settings that meet the
baseline in an assigned fine-grained policy, without assuming coverage.
Where no assignments are reported, it does not treat the policy as mitigating
the default-policy findings or include its settings as findings. Weak settings
for reported assignments to other users or groups are included, without
assuming their membership or effective policy. Verify assignments and the
effective policy for individual accounts.

## Why it matters

Weak password and lockout settings make password spraying, brute force, and
credential stuffing practical, increasing the likelihood of account compromise.

## Findings

| Finding ID | Title |
|------------|-------|
| PASS-001 | Weak Password and Account Lockout Policy |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check
  (`--pass-pol`).

## References

- [mollysec: Password Spraying Explained](https://mollysec.com/posts/password-spray/)
- [hackndo: password spraying](https://en.hackndo.com/password-spraying/)
- [Microsoft: password policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy)
- [Microsoft: account lockout policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy)
- [NCSC: updating your password approach](https://www.ncsc.gov.uk/collection/passwords/updating-your-approach)