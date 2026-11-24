"""Evidence-specific introductions for related findings."""

from ad_kit.core.finding import Finding

_TOPICS = {
    "SMB": ("SMB", "SMB security"),
    "LDAP": ("LDAP", "LDAP security"),
    "PASS": ("Password and account configuration", "password and account configuration"),
    "ASREP": ("AS-REP roasting", "Kerberos pre-authentication"),
    "KERB": ("Kerberoasting", "Kerberos service account"),
    "DELEG": ("Kerberos delegation", "Kerberos delegation"),
    "ADCS": ("Certificate services", "certificate services"),
    "PRIV": ("Privileged accounts", "privileged access and account"),
    "LA": ("Administrative access", "administrative access"),
}

# Each entry describes an observed finding and a possible, not established, impact.
_DETAILS = {
    "SMB-001": ("systems not requiring SMB signing", "authentication relay"),
    "SMB-002": ("systems supporting SMBv1", "exploitation of vulnerable legacy services"),
    "SMB-003": ("empty-credential SMB enumeration", "unauthorised reconnaissance"),
    "SMB-004": (
        "shares with write-related permissions reported for a standard user",
        "unauthorised file modification or authentication capture and relay where effective "
        "file-write access exists",
    ),
    "LDAP-001": ("LDAP signing not being enforced", "authentication relay or traffic tampering"),
    "LDAP-002": ("LDAP channel binding not being enforced", "authentication relay"),
    "LDAP-003": ("anonymous LDAP binds", "directory enumeration where separately permitted"),
    "PASS-001": ("weak password or account lockout settings", "password guessing"),
    "PASS-002": (
        "accounts configured without a required password",
        "exposure of accounts without appropriate credentials",
    ),
    "PASS-003": (
        "accounts with non-expiring passwords",
        "prolonged exposure of compromised credentials",
    ),
    "ASREP-001": (
        "accounts without Kerberos pre-authentication",
        "offline password cracking",
    ),
    "ASREP-002": (
        "affected accounts in monitored privileged groups",
        "unauthorised access if privileged credentials are recovered",
    ),
    "KERB-001": ("accounts associated with service principal names", "offline password cracking"),
    "KERB-002": (
        "service principal names assigned to privileged accounts",
        "unauthorised access if privileged credentials are recovered",
    ),
    "DELEG-001": ("unconstrained delegation", "impersonation following system compromise"),
    "DELEG-002": (
        "constrained delegation with protocol transition",
        "impersonation following delegated account compromise",
    ),
    "DELEG-003": (
        "delegation configured on privileged accounts",
        "expanded access following privileged account compromise",
    ),
    "ADCS-ESC1": ("certificate templates vulnerable to ESC1", "certificate-based impersonation"),
    "ADCS-ESC8": ("certificate enrolment vulnerable to ESC8", "authentication relay"),
    "ADCS-ESC15": ("certificate templates vulnerable to ESC15", "certificate-based impersonation"),
    "PRIV-001": ("excessive privileged group membership", "privileged account compromise"),
    "PRIV-002": (
        "a large population of accounts marked as protected",
        "unreviewed account protections or stale account attributes",
    ),
    "PRIV-003": ("an enabled built-in Guest account", "unattributed access where permitted"),
    "PRIV-004": ("an enabled built-in Administrator account", "high-impact account compromise"),
    "PRIV-005": ("unexpected directory replication rights", "exposure of directory credentials"),
    "LA-001": (
        "standard user administrative access to domain-joined systems",
        "lateral movement following account compromise",
    ),
    "LA-002": (
        "standard user administrative access to domain controllers",
        "domain compromise following account compromise",
    ),
}


def _join(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + ", and " + items[-1]


def group_findings(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Group findings by their ID prefix, preserving first-seen topic order."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        prefix, separator, _ = finding.id.partition("-")
        key = prefix if separator else finding.id
        groups.setdefault(key, []).append(finding)
    return list(groups.items())


def group_title(topic: str) -> str:
    return _TOPICS.get(topic, (topic, topic))[0]


def group_introduction(topic: str, findings: list[Finding]) -> str:
    """Summarise related findings without assuming unobserved evidence."""
    observations = []
    impacts = []
    for finding in findings:
        observation, impact = _DETAILS.get(
            finding.id,
            (f"the finding '{finding.title}'", "risks to systems, accounts, or data"),
        )
        if observation not in observations:
            observations.append(observation)
        if impact not in impacts:
            impacts.append(impact)
    topic_name = _TOPICS.get(topic, (topic, topic))[1]
    return (
        f"The assessment identified multiple {topic_name} observations, including "
        f"{_join(observations)}.\n\n"
        f"Depending on the circumstances, these observations could contribute to "
        f"{_join(impacts)}."
    )
