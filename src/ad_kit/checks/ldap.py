"""
LDAP-related assessment checks.
"""

from ad_kit.core.checks import run_check
from ad_kit.core.util import get_artefacts_dir


def ldap_check() -> list[dict]:
    """
    Execute LDAP checks for a Domain Controller.
    """

    dc_ips_file = (get_artefacts_dir() / "dc-ips.txt")

    output = run_check(
        "ldap",
        ["nxc", "ldap", str(dc_ips_file),
            "-u", "",
            "-p", "",
        ],
    )

    results = {}

    for line in output.splitlines():

        if not line.startswith("LDAP"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        dc_ip = parts[1]

        if dc_ip not in results:

            results[dc_ip] = {
                "dc_ip": dc_ip,
                "signing": "Unknown",
                "channel_binding": "Unknown",
                "anonymous_bind": "Unknown",
            }

        lower = line.lower()

        # LDAP Signing
        if "signing:" in lower:

            start = lower.find("signing:")
            end = lower.find(")", start)

            if start != -1 and end != -1:

                signing = lower[start + 8:end].strip()

                if signing == "none":
                    signing = "Not Required"

                results[dc_ip]["signing"] = signing

        # Channel Binding
        if "channel binding:" in lower:

            start = lower.find("channel binding:")
            end = lower.find(")", start)

            if start != -1 and end != -1:

                channel_binding = (lower[start + 16:end].strip())

                if channel_binding == "no tls cert":
                    channel_binding = "Not Configured"

                results[dc_ip]["channel_binding"] = channel_binding

        # Anonymous Bind
        if ("successful bind must be completed" in lower):
            results[dc_ip]["anonymous_bind"] = ("Disabled")

        elif (
            "[+]" in lower
            and "\\:" in lower
            and results[dc_ip]["anonymous_bind"]
                == "Unknown"
        ):
            results[dc_ip]["anonymous_bind"] = ("Enabled")

    return sorted(results.values(), key=lambda result: result["dc_ip"])