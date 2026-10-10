"""Close security group rules that open SSH, RDP or every port to the internet."""

from __future__ import annotations

from ..core import IGNORE_TAG, Action, Context, Event, api_call, has_ignore_tag, responder

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
INTERNET_V4 = "0.0.0.0/0"
INTERNET_V6 = "::/0"


def _group_id(event: Event) -> str | None:
    params = event.params
    if params.get("groupId"):
        return params["groupId"]
    modify = params.get("ModifySecurityGroupRulesRequest") or {}
    return modify.get("GroupId")


def _what_is_open(perm: dict) -> str | None:
    """Describe the risky part of a rule, or None if it is fine."""
    protocol = str(perm.get("IpProtocol"))
    if protocol == "-1":
        return "every port"
    if protocol not in ("tcp", "6"):
        return None
    low, high = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    if low <= 0 and high >= 65535:
        return "every port"
    names = [f"{label} (port {port})" for port, label in ADMIN_PORTS.items() if low <= port <= high]
    return " and ".join(names) or None


@responder(
    "sg_open",
    "Removes security group rules that open SSH, RDP or every port to 0.0.0.0/0 or ::/0.",
    api_call("ec2", "AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"),
)
def sg_open(event: Event, ctx: Context) -> list[Action]:
    group_id = _group_id(event)
    if not group_id:
        return []
    ec2 = ctx.aws("ec2")
    groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    if not groups:
        return []
    group = groups[0]
    ignored = has_ignore_tag(group.get("Tags"))

    actions = []
    for perm in group.get("IpPermissions", []):
        what = _what_is_open(perm)
        v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == INTERNET_V4]
        v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == INTERNET_V6]
        if not what or not (v4 or v6):
            continue

        action = Action(
            responder="sg_open",
            severity="critical",
            resource=f"{group_id} ({group.get('GroupName', '')})",
            problem=f"{what[0].upper()}{what[1:]} open to the whole internet.",
            response="Would remove the internet part of this rule. Other sources in the rule stay.",
            context=event.who_and_when(),
        )
        if ignored:
            action.response = f"Group is tagged {IGNORE_TAG}=true, so it was left alone."
        elif ctx.fix:
            # Revoke only the internet ranges, so rules for private ranges stay.
            revoke = {k: perm[k] for k in ("IpProtocol", "FromPort", "ToPort") if k in perm}
            if v4:
                revoke["IpRanges"] = [{"CidrIp": INTERNET_V4}]
            if v6:
                revoke["Ipv6Ranges"] = [{"CidrIpv6": INTERNET_V6}]
            ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[revoke])
            action.response = "Removed the internet part of this rule. Other sources in the rule stay."
            action.fixed = True
        actions.append(action)
    return actions
