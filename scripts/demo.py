"""Run watchpost against a fake AWS account (moto), no real AWS needed.

    pip install -e ".[dev]"
    python scripts/demo.py            # fix mode
    python scripts/demo.py --alert    # alert mode, nothing gets changed
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
    os.environ[key] = "demo"
os.environ["AWS_DEFAULT_REGION"] = "ca-central-1"

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from watchpost.core import Action, Event, Settings  # noqa: E402
from watchpost.handler import format_alert, handle  # noqa: E402

REGION = "ca-central-1"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def event(sample, **params):
    raw = json.loads((ROOT / "events" / f"{sample}.json").read_text())
    raw["detail"].setdefault("requestParameters", {})
    if raw["detail"]["requestParameters"] is not None:
        raw["detail"]["requestParameters"].update(params)
    return raw


def setup():
    """Make a small, badly set up account. Returns the ids the events need."""
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    iam = boto3.client("iam", region_name="us-east-1")
    ct = boto3.client("cloudtrail", region_name=REGION)

    s3.create_bucket(Bucket="acme-reports", CreateBucketConfiguration={"LocationConstraint": REGION})

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    instance = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[sg])
    instance_id = instance["Instances"][0]["InstanceId"]

    iam.create_user(UserName="dev-alex")
    iam.attach_user_policy(UserName="dev-alex", PolicyArn=ADMIN)
    key_id = iam.create_access_key(UserName="dev-alex")["AccessKey"]["AccessKeyId"]

    s3.create_bucket(Bucket="acme-trail", CreateBucketConfiguration={"LocationConstraint": REGION})
    trail = ct.create_trail(Name="main", S3BucketName="acme-trail")["TrailARN"]
    ct.stop_logging(Name="main")
    return {"sg": sg, "instance": instance_id, "key": key_id, "trail": trail}


def main():
    mode = "alert" if "--alert" in sys.argv else "fix"
    with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
        ids = setup()

        gd_instance = event("guardduty-instance")
        gd_instance["detail"]["resource"]["instanceDetails"]["instanceId"] = ids["instance"]
        gd_key = event("guardduty-access-key")
        gd_key["detail"]["resource"]["accessKeyDetails"]["accessKeyId"] = ids["key"]

        scenarios = [
            ("Someone removes a bucket's public access block", event("s3-public-access-block-deleted")),
            ("Someone opens SSH to the internet", event("sg-ssh-open", groupId=ids["sg"])),
            ("Someone gives a user full admin", event("iam-admin-to-user")),
            ("Someone turns off CloudTrail", event("cloudtrail-stopped", name=ids["trail"])),
            ("Someone signs in as root without MFA", event("root-console-login")),
            ("GuardDuty sees a server mining bitcoin", gd_instance),
            ("GuardDuty sees a stolen access key", gd_key),
        ]

        print(f"watchpost demo, mode = {mode}\n")
        for i, (story, raw) in enumerate(scenarios, 1):
            print(f"{i}. {story}")
            result = handle(raw, Settings(mode=mode))
            for action in result["actions"]:
                subject, body = format_alert(Action(**action), mode, Event(raw))
                print(f"   {subject}")
                print("   " + body.replace("\n", "\n   "))
            print()


if __name__ == "__main__":
    main()
