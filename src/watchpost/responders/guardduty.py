"""Respond to GuardDuty findings: quarantine a hacked server, or turn off a leaked access key."""

from __future__ import annotations

from ..core import IGNORE_TAG, Action, Context, Event, has_ignore_tag, responder

QUARANTINE_SG = "watchpost-quarantine"
QUARANTINE_TAG = "watchpost:quarantined"


def _severity(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _finding(resource_type: str):
    def match(event: Event) -> bool:
        return (
            event.source == "aws.guardduty"
            and event.detail_type == "GuardDuty Finding"
            and (event.detail.get("resource") or {}).get("resourceType") == resource_type
        )

    return match


def _context(event: Event) -> str:
    d = event.detail
    return f"GuardDuty finding {d.get('type', '')} (severity {d.get('severity', '?')}, id {d.get('id', '?')})"


# ---------- Hacked server ----------


@responder(
    "gd_instance",
    "Quarantines an EC2 instance from a GuardDuty finding: cuts its network, snapshots its disks, blocks termination.",
    _finding("Instance"),
)
def gd_instance(event: Event, ctx: Context) -> list[Action]:
    score = float(event.detail.get("severity", 0))
    if score < ctx.settings.min_guardduty_severity:
        return []
    instance_id = (event.detail["resource"].get("instanceDetails") or {}).get("instanceId")
    if not instance_id:
        return []

    ec2 = ctx.aws("ec2")
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    if not reservations:
        return []
    instance = reservations[0]["Instances"][0]
    tags = instance.get("Tags", [])

    action = Action(
        responder="gd_instance",
        severity=_severity(score),
        resource=f"EC2 instance {instance_id}",
        problem=event.detail.get("title") or "GuardDuty thinks this server is compromised.",
        response=(
            "Would quarantine it: swap its security groups for one with no rules, "
            "snapshot its disks for evidence, and block termination. The server keeps running."
        ),
        context=_context(event),
    )

    if has_ignore_tag(tags):
        action.response = f"Instance is tagged {IGNORE_TAG}=true, so it was left alone."
        return [action]
    if any(t.get("Key") == QUARANTINE_TAG for t in tags):
        action.response = "Already quarantined earlier, nothing more to do."
        return [action]
    if not ctx.fix:
        return [action]

    finding_id = event.detail.get("id", "unknown")
    sg_id = _quarantine_group(ec2, instance["VpcId"])

    snapshots = []
    for mapping in instance.get("BlockDeviceMappings", []):
        volume = (mapping.get("Ebs") or {}).get("VolumeId")
        if volume:
            snap = ec2.create_snapshot(
                VolumeId=volume,
                Description=f"watchpost evidence for {instance_id}, finding {finding_id}",
                TagSpecifications=[
                    {"ResourceType": "snapshot", "Tags": [{"Key": QUARANTINE_TAG, "Value": finding_id}]}
                ],
            )
            snapshots.append(snap["SnapshotId"])

    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])
    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": QUARANTINE_TAG, "Value": finding_id}])

    old = ", ".join(g["GroupId"] for g in instance.get("SecurityGroups", [])) or "none"
    action.response = (
        f"Quarantined it. Security groups changed from {old} to {sg_id}. "
        f"Snapshots taken: {', '.join(snapshots) or 'none'}. Termination is blocked. The server is still running."
    )
    action.fixed = True
    return [action]


def _quarantine_group(ec2, vpc_id: str) -> str:
    """Find or make a security group with no inbound and no outbound rules in this VPC."""
    found = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": [QUARANTINE_SG]}]
    )["SecurityGroups"]
    if found:
        return found[0]["GroupId"]
    sg_id = ec2.create_security_group(
        GroupName=QUARANTINE_SG,
        Description="watchpost quarantine: no traffic in or out",
        VpcId=vpc_id,
    )["GroupId"]
    # New groups allow all outbound traffic by default. Remove that.
    ec2.revoke_security_group_egress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    return sg_id


# ---------- Leaked access key ----------


@responder(
    "gd_access_key",
    "Turns off an IAM user's access key when GuardDuty says it is being misused.",
    _finding("AccessKey"),
)
def gd_access_key(event: Event, ctx: Context) -> list[Action]:
    score = float(event.detail.get("severity", 0))
    if score < ctx.settings.min_guardduty_severity:
        return []
    key = event.detail["resource"].get("accessKeyDetails") or {}
    key_id, user, user_type = key.get("accessKeyId", ""), key.get("userName", ""), key.get("userType", "")

    action = Action(
        responder="gd_access_key",
        severity=_severity(score),
        resource=f"access key {key_id} ({user_type} {user})",
        problem=event.detail.get("title") or "GuardDuty thinks this access key is being misused.",
        response="Would set the access key to Inactive.",
        context=_context(event),
    )

    if user_type != "IAMUser":
        action.response = (
            "Alert only. This is not a long-lived IAM user key. For role credentials, "
            "revoke the role's active sessions in the IAM console."
        )
        return [action]

    iam = ctx.aws("iam")
    if has_ignore_tag(iam.list_user_tags(UserName=user).get("Tags")):
        action.response = f"User is tagged {IGNORE_TAG}=true, so it was left alone."
        return [action]

    keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    current = next((k for k in keys if k["AccessKeyId"] == key_id), None)
    if current is None:
        action.response = "The key no longer exists, nothing to do."
        return [action]
    if current["Status"] == "Inactive":
        action.response = "The key is already Inactive."
        return [action]

    if ctx.fix:
        iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
        action.response = "Set the access key to Inactive. Make a new key for the user once you know what happened."
        action.fixed = True
    return [action]
