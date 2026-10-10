"""Turn the S3 public access block back on when someone weakens it."""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..core import IGNORE_TAG, Action, Context, Event, api_call, has_ignore_tag, responder

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

WATCHED = ("PutBucketAcl", "PutBucketPolicy", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock")


@responder(
    "s3_public",
    "Turns the bucket's public access block back on after someone weakens it or changes the ACL or policy.",
    api_call("s3", *WATCHED),
)
def s3_public(event: Event, ctx: Context) -> list[Action]:
    bucket = event.params.get("bucketName")
    if not bucket:
        return []
    s3 = ctx.aws("s3")

    try:
        current = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        current = {}

    off = [k for k in ALL_ON if not current.get(k)]
    if not off:
        return []  # already fully blocked (this is also how we skip our own fix event)

    action = Action(
        responder="s3_public",
        severity="high",
        resource=f"s3://{bucket}",
        problem=f"Public access block was weakened ({', '.join(off)} off).",
        response="Would turn all four public access block settings back on.",
        context=event.who_and_when(),
    )

    if _ignored(s3, bucket):
        action.response = f"Bucket is tagged {IGNORE_TAG}=true, so it was left alone."
        return [action]

    if ctx.fix:
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=ALL_ON)
        action.response = "Turned all four public access block settings back on."
        action.fixed = True
    return [action]


def _ignored(s3, bucket: str) -> bool:
    try:
        return has_ignore_tag(s3.get_bucket_tagging(Bucket=bucket).get("TagSet"))
    except ClientError as err:
        if err.response["Error"]["Code"] in ("NoSuchTagSet", "NoSuchTagSetError"):
            return False
        raise
