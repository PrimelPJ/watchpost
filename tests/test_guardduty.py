from .conftest import client, load_event, run


def make_instance(tags=None):
    ec2 = client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    web = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    kwargs = {"ImageId": "ami-12c6146b", "MinCount": 1, "MaxCount": 1, "SubnetId": subnet, "SecurityGroupIds": [web]}
    if tags:
        kwargs["TagSpecifications"] = [{"ResourceType": "instance", "Tags": tags}]
    instance = ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]
    return ec2, instance, vpc


def instance_event(instance_id, severity=8.0):
    raw = load_event("guardduty-instance", severity=severity)
    raw["detail"]["resource"]["instanceDetails"]["instanceId"] = instance_id
    return raw


def describe(ec2, instance_id):
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def test_quarantines_instance(aws):
    ec2, instance_id, vpc = make_instance()
    [action] = run(instance_event(instance_id))["actions"]
    assert action["fixed"] is True

    groups = [g["GroupName"] for g in describe(ec2, instance_id)["SecurityGroups"]]
    assert groups == ["watchpost-quarantine"]

    qsg = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["watchpost-quarantine"]}])["SecurityGroups"][0]
    assert qsg["IpPermissions"] == [] and qsg["IpPermissionsEgress"] == []

    protected = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiTermination")
    assert protected["DisableApiTermination"]["Value"] is True

    snaps = ec2.describe_snapshots(Filters=[{"Name": "tag-key", "Values": ["watchpost:quarantined"]}])["Snapshots"]
    assert len(snaps) >= 1


def test_second_finding_does_not_repeat_work(aws):
    ec2, instance_id, _ = make_instance()
    run(instance_event(instance_id))
    [action] = run(instance_event(instance_id))["actions"]
    assert "Already quarantined" in action["response"]
    snaps = ec2.describe_snapshots(Filters=[{"Name": "tag-key", "Values": ["watchpost:quarantined"]}])["Snapshots"]
    assert len(snaps) == 1


def test_low_severity_is_skipped(aws):
    ec2, instance_id, _ = make_instance()
    assert run(instance_event(instance_id, severity=5.0))["actions"] == []
    assert run(instance_event(instance_id, severity=5.0), min_guardduty_severity=4.0)["actions"]


def test_alert_mode_and_ignore_tag(aws):
    ec2, instance_id, _ = make_instance(tags=[{"Key": "watchpost:ignore", "Value": "true"}])
    assert "left alone" in run(instance_event(instance_id))["actions"][0]["response"]

    ec2, other, _ = make_instance()
    run(instance_event(other), mode="alert")
    assert [g["GroupName"] for g in describe(ec2, other)["SecurityGroups"]] == ["web"]


def key_event(key_id, user_type="IAMUser"):
    raw = load_event("guardduty-access-key")
    raw["detail"]["resource"]["accessKeyDetails"].update(accessKeyId=key_id, userType=user_type)
    return raw


def test_turns_off_leaked_key(aws):
    iam = client("iam", "us-east-1")
    iam.create_user(UserName="dev-alex")
    key = iam.create_access_key(UserName="dev-alex")["AccessKey"]["AccessKeyId"]
    [action] = run(key_event(key))["actions"]
    assert action["fixed"] is True
    assert iam.list_access_keys(UserName="dev-alex")["AccessKeyMetadata"][0]["Status"] == "Inactive"
    assert "already Inactive" in run(key_event(key))["actions"][0]["response"]


def test_role_credentials_are_only_reported(aws):
    [action] = run(key_event("ASIAEXAMPLE", user_type="AssumedRole"))["actions"]
    assert action["fixed"] is False
    assert "revoke" in action["response"]
