from .conftest import client, load_event, run

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def make_user(tags=None):
    iam = client("iam", "us-east-1")
    iam.create_user(UserName="dev-alex", Tags=tags or [])
    iam.attach_user_policy(UserName="dev-alex", PolicyArn=ADMIN)
    return iam


def attached(iam):
    return [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName="dev-alex")["AttachedPolicies"]]


def test_detaches_admin_from_user(aws):
    iam = make_user()
    result = run(load_event("iam-admin-to-user"))
    assert attached(iam) == []
    assert result["actions"][0]["severity"] == "critical"


def test_user_with_ignore_tag_keeps_admin(aws):
    iam = make_user(tags=[{"Key": "watchpost:ignore", "Value": "true"}])
    run(load_event("iam-admin-to-user"))
    assert attached(iam) == [ADMIN]


def test_role_is_only_reported(aws):
    result = run(load_event("iam-admin-to-role"))
    assert result["actions"][0]["fixed"] is False
    assert "ci-deploy" in result["actions"][0]["resource"]


def test_other_policies_are_ignored(aws):
    make_user()
    raw = load_event("iam-admin-to-user", params={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
    assert run(raw)["actions"] == []


def test_root_login_without_mfa(aws):
    [action] = run(load_event("root-console-login"))["actions"]
    assert action["severity"] == "critical"
    assert "without MFA" in action["problem"]
    assert action["context"].startswith("the root user signed in")


def test_failed_root_login_is_ignored(aws):
    raw = load_event("root-console-login", responseElements={"ConsoleLogin": "Failure"})
    assert run(raw)["actions"] == []


def test_root_access_key(aws):
    [action] = run(load_event("root-access-key-created"))["actions"]
    assert "root" in action["problem"].lower()


def make_trail():
    s3 = client("s3")
    s3.create_bucket(Bucket="acme-trail", CreateBucketConfiguration={"LocationConstraint": "ca-central-1"})
    ct = client("cloudtrail")
    arn = ct.create_trail(Name="main", S3BucketName="acme-trail")["TrailARN"]
    return ct, arn


def test_turns_logging_back_on(aws):
    ct, arn = make_trail()
    ct.stop_logging(Name="main")
    result = run(load_event("cloudtrail-stopped", params={"name": arn}))
    assert ct.get_trail_status(Name="main")["IsLogging"] is True
    assert result["actions"][0]["fixed"] is True


def test_logging_already_on_does_nothing(aws):
    ct, arn = make_trail()
    ct.start_logging(Name="main")
    assert run(load_event("cloudtrail-stopped", params={"name": arn}))["actions"] == []


def test_deleted_trail_is_reported(aws):
    [action] = run(load_event("cloudtrail-deleted"))["actions"]
    assert action["severity"] == "critical"
    assert action["fixed"] is False
