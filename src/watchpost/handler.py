"""Lambda entry point. EventBridge sends events here, watchpost picks the right responder."""

from __future__ import annotations

import json
import logging

import boto3

from . import responders  # noqa: F401  (adds the responders to the list)
from .core import RESPONDERS, Action, Context, Event, Settings

log = logging.getLogger("watchpost")
log.setLevel(logging.INFO)


class WatchpostError(Exception):
    """At least one responder failed. Raised after alerts go out, so Lambda retries and the DLQ catches it."""


def lambda_handler(event: dict, context: object = None) -> dict:
    return handle(event, Settings.from_env())


def handle(raw: dict, settings: Settings) -> dict:
    event = Event(raw)
    ctx = Context(settings, event.region)

    matched: list[str] = []
    actions: list[Action] = []
    failed = False

    for r in RESPONDERS:
        if r.name in settings.disabled or not r.match(event):
            continue
        matched.append(r.name)
        try:
            actions += r.run(event, ctx)
        except Exception as err:  # report every failure, never fail silently
            log.exception("responder %s failed", r.name)
            failed = True
            actions.append(
                Action(
                    responder=r.name,
                    severity="high",
                    resource=_guess_resource(event),
                    problem=f"watchpost could not finish handling {event.name or event.detail_type}.",
                    response="Nothing may have been changed. Check the Lambda logs and fix this by hand.",
                    error=f"{type(err).__name__}: {err}",
                    context=event.who_and_when(),
                )
            )

    if len(actions) > settings.max_actions_per_event:
        actions = actions[:settings.max_actions_per_event]

    for action in actions:
        log.info(json.dumps({"watchpost": action.to_dict(), "mode": settings.mode, "account": event.account}))
        if settings.topic_arn:
            notify(settings.topic_arn, action, settings.mode, event)

    result = {"mode": settings.mode, "matched": matched, "actions": [a.to_dict() for a in actions]}
    if failed:
        raise WatchpostError(json.dumps(result))
    return result


def format_alert(action: Action, mode: str, event: Event) -> tuple[str, str]:
    subject = f"watchpost {action.severity.upper()}: {action.problem}"
    if len(subject) > 100:  # SNS subject limit
        subject = subject[:97] + "..."
    lines = [
        f"Problem: {action.problem}",
        f"Resource: {action.resource}",
        f"What happened: {action.context or 'unknown'}",
        f"What watchpost did: {action.response}",
    ]
    if action.error:
        lines.append(f"Error: {action.error}")
    lines += ["", f"Severity: {action.severity}", f"Mode: {mode}", f"Account: {event.account or 'unknown'}", f"Region: {event.region}"]
    return subject, "\n".join(lines)


def notify(topic_arn: str, action: Action, mode: str, event: Event) -> None:
    subject, body = format_alert(action, mode, event)
    region = topic_arn.split(":")[3]  # the topic can live in a different region than the event
    try:
        boto3.client("sns", region_name=region).publish(TopicArn=topic_arn, Subject=subject, Message=body)
    except Exception:
        # The alert is still in the logs. Do not let a broken topic hide the fix.
        log.exception("could not publish alert to %s", topic_arn)


def _guess_resource(event: Event) -> str:
    p = event.params
    for key in ("bucketName", "groupId", "userName", "roleName", "name"):
        if p.get(key):
            return str(p[key])
    return "unknown"


def format_remediation_alert(event_name: str, resource_arn: str, principal: str, region: str) -> str:
    """Format a remediation alert for SNS notification.

    Produces a structured, human-readable alert that includes the
    offending action, who did it, what was remediated, and where.
    """
    return (
        f"[WATCHPOST REMEDIATION]\n"
        f"Event:     {event_name}\n"
        f"Resource:  {resource_arn}\n"
        f"Principal: {principal}\n"
        f"Region:    {region}\n"
        f"Action:    Auto-remediated. Review CloudTrail for original change."
    )


def format_alert_json(event_name: str, resource_arn: str, principal: str, region: str) -> dict:
    """Structured alert payload for downstream processing."""
    return {
        "source": "watchpost",
        "event": event_name,
        "resource": resource_arn,
        "principal": principal,
        "region": region,
        "action": "auto_remediated",
    }
