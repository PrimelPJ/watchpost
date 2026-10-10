"""Catch full admin access being handed out, and root user activity."""

from __future__ import annotations

from ..core import IGNORE_TAG, Action, Context, Event, api_call, has_ignore_tag, responder

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"


@responder(
    "iam_admin",
    "Detaches AdministratorAccess from IAM users. Admin on roles and groups is reported, not removed.",
    api_call("iam", "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"),
)
def iam_admin(event: Event, ctx: Context) -> list[Action]:
    if event.params.get("policyArn") != ADMIN_POLICY:
        return []

    if event.name == "AttachUserPolicy":
        user = event.params.get("userName", "")
        action = Action(
            responder="iam_admin",
            severity="critical",
            resource=f"IAM user {user}",
            problem="AdministratorAccess was attached directly to a user. Admin should come from a role you assume.",
            response="Would detach AdministratorAccess from the user.",
            context=event.who_and_when(),
        )
        iam = ctx.aws("iam")
        if has_ignore_tag(iam.list_user_tags(UserName=user).get("Tags")):
            action.response = f"User is tagged {IGNORE_TAG}=true, so it was left alone."
        elif ctx.fix:
            iam.detach_user_policy(UserName=user, PolicyArn=ADMIN_POLICY)
            action.response = "Detached AdministratorAccess from the user."
            action.fixed = True
        return [action]

    kind, key = ("role", "roleName") if event.name == "AttachRolePolicy" else ("group", "groupName")
    return [
        Action(
            responder="iam_admin",
            severity="high",
            resource=f"IAM {kind} {event.params.get(key, '')}",
            problem=f"AdministratorAccess was attached to a {kind}.",
            response=f"Left in place, since some {kind}s need admin. Please check this was expected.",
            context=event.who_and_when(),
        )
    ]


def _is_root(event: Event) -> bool:
    return (event.detail.get("userIdentity") or {}).get("type") == "Root"


def _root_activity(event: Event) -> bool:
    if not _is_root(event) or event.failed:
        return False
    if event.detail_type == "AWS Console Sign In via CloudTrail" and event.name == "ConsoleLogin":
        return (event.detail.get("responseElements") or {}).get("ConsoleLogin") == "Success"
    return api_call("iam", "CreateAccessKey")(event) and not event.params.get("userName")


@responder(
    "root_activity",
    "Alerts when someone signs in as the root user or creates root access keys.",
    _root_activity,
)
def root_activity(event: Event, ctx: Context) -> list[Action]:
    if event.name == "ConsoleLogin":
        mfa = (event.detail.get("additionalEventData") or {}).get("MFAUsed") == "Yes"
        return [
            Action(
                responder="root_activity",
                severity="high" if mfa else "critical",
                resource=f"root user of account {event.account}",
                problem="Someone signed in as the root user" + ("." if mfa else " without MFA."),
                response="Alert only. If this was not you, change the root password and check recent activity now.",
                context=event.who_and_when(),
            )
        ]
    return [
        Action(
            responder="root_activity",
            severity="critical",
            resource=f"root user of account {event.account}",
            problem="Access keys were created for the root user. Root keys can do anything and cannot be limited.",
            response="Alert only. Delete the root access key unless you have a very good reason to keep it.",
            context=event.who_and_when(),
        )
    ]
