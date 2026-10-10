from .conftest import client, load_event, run


def make_group(rules, tags=None):
    ec2 = client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=rules)
    if tags:
        ec2.create_tags(Resources=[sg], Tags=tags)
    return ec2, sg


def ingress(ec2, sg):
    return ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]


def tcp(port, *cidrs, to=None):
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": to or port, "IpRanges": [{"CidrIp": c} for c in cidrs]}


def test_removes_ssh_open_to_internet_but_keeps_private_range(aws):
    ec2, sg = make_group([tcp(22, "0.0.0.0/0", "10.0.0.0/8"), tcp(443, "0.0.0.0/0")])
    result = run(load_event("sg-ssh-open", params={"groupId": sg}))

    [action] = result["actions"]
    assert action["fixed"] is True
    assert "SSH (port 22)" in action["problem"]

    rules = {(p["FromPort"], r["CidrIp"]) for p in ingress(ec2, sg) for r in p["IpRanges"]}
    assert (22, "0.0.0.0/0") not in rules
    assert (22, "10.0.0.0/8") in rules  # private range kept
    assert (443, "0.0.0.0/0") in rules  # https left alone


def test_all_traffic_rule(aws):
    ec2, sg = make_group([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    result = run(load_event("sg-ssh-open", params={"groupId": sg}))
    assert "Every port" in result["actions"][0]["problem"]
    assert ingress(ec2, sg) == []


def test_rdp_inside_range_and_ipv6(aws):
    ec2, sg = make_group([{"IpProtocol": "tcp", "FromPort": 3000, "ToPort": 4000, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    result = run(load_event("sg-ssh-open", params={"groupId": sg}))
    assert "RDP (port 3389)" in result["actions"][0]["problem"]
    assert ingress(ec2, sg) == []


def test_alert_mode_and_ignore_tag(aws):
    ec2, sg = make_group([tcp(22, "0.0.0.0/0")])
    assert run(load_event("sg-ssh-open", params={"groupId": sg}), mode="alert")["actions"][0]["fixed"] is False
    assert len(ingress(ec2, sg)) == 1

    ec2.create_tags(Resources=[sg], Tags=[{"Key": "watchpost:ignore", "Value": "true"}])
    result = run(load_event("sg-ssh-open", params={"groupId": sg}))
    assert "left alone" in result["actions"][0]["response"]
    assert len(ingress(ec2, sg)) == 1


def test_safe_rules_do_nothing(aws):
    _, sg = make_group([tcp(443, "0.0.0.0/0"), tcp(22, "10.0.0.0/8")])
    assert run(load_event("sg-ssh-open", params={"groupId": sg}))["actions"] == []
