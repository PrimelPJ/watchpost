from .conftest import client, load_event, run

ALL_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def make_bucket(name="acme-reports", tags=None):
    s3 = client("s3")
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": "ca-central-1"})
    if tags:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": tags})
    return s3


def block(s3, name="acme-reports"):
    return s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]


def test_fix_mode_turns_block_back_on(aws):
    s3 = make_bucket()
    result = run(load_event("s3-public-access-block-deleted"))
    assert block(s3) == ALL_ON
    [action] = result["actions"]
    assert action["fixed"] is True
    assert "weakened" in action["problem"] and "BlockPublicPolicy" in action["problem"]
    assert "dev-alex" in action["context"]


def test_alert_mode_changes_nothing(aws):
    s3 = make_bucket()
    s3.put_public_access_block(Bucket="acme-reports", PublicAccessBlockConfiguration={**ALL_ON, "BlockPublicPolicy": False})
    result = run(load_event("s3-acl-public-read"), mode="alert")
    assert block(s3)["BlockPublicPolicy"] is False
    assert result["actions"][0]["fixed"] is False
    assert result["actions"][0]["response"].startswith("Would")


def test_already_blocked_does_nothing(aws):
    # This is also what happens when watchpost sees the event from its own fix.
    s3 = make_bucket()
    s3.put_public_access_block(Bucket="acme-reports", PublicAccessBlockConfiguration=ALL_ON)
    assert run(load_event("s3-acl-public-read"))["actions"] == []


def test_ignore_tag(aws):
    s3 = make_bucket(tags=[{"Key": "watchpost:ignore", "Value": "true"}])
    result = run(load_event("s3-public-access-block-deleted"))
    assert "left alone" in result["actions"][0]["response"]
    assert result["actions"][0]["fixed"] is False


def test_failed_call_is_ignored(aws):
    make_bucket()
    raw = load_event("s3-acl-public-read", errorCode="AccessDenied")
    assert run(raw)["matched"] == []
