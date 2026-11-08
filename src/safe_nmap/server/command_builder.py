"""Build fixed Nmap argv lists from validated plans; never accept raw flags."""

from safe_nmap.shared.schemas import ValidatedPlan


def build_nmap_command(plan: ValidatedPlan) -> list[str]:
    """Build the supported TCP scan command from a server-created plan."""
    arguments = ["nmap", "-n", "-sT", "-T3", "-oX", "-"]
    if plan.service_detection:
        arguments.append("-sV")

    arguments.extend(("-p", ",".join(str(port) for port in plan.ports)))
    arguments.append(plan.resolved_ip)
    return arguments
