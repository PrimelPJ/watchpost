"""The building blocks: events, actions, settings, and the responder list."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable

import boto3

IGNORE_TAG = "watchpost:ignore"
SEVERITIES = ["low", "medium", "high", "critical"]


class Event:
    """An EventBridge event, with easy access to the CloudTrail fields we use."""

    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.detail: dict[str, Any] = raw.get("detail") or {}

    @property
    def source(self) -> str:
        return self.raw.get("source", "")

    @property
    def detail_type(self) -> str:
        return self.raw.get("detail-type", "")

    @property
    def region(self) -> str:
        return self.detail.get("awsRegion") or self.raw.get("region") or os.environ.get("AWS_REGION", "us-east-1")

    @property
    def account(self) -> str:
        return self.raw.get("account", "")

    @property
    def name(self) -> str:
        return self.detail.get("eventName", "")

    @property
    def params(self) -> dict[str, Any]:
        return self.detail.get("requestParameters") or {}

    @property
    def failed(self) -> bool:
        """The API call was denied or failed, so nothing changed."""
        return bool(self.detail.get("errorCode"))

    @property
    def actor(self) -> str:
        who = self.detail.get("userIdentity") or {}
        if who.get("type") == "Root":
            return "the root user"
        return who.get("arn") or who.get("principalId") or "unknown"

    def who_and_when(self) -> str:
        ip = self.detail.get("sourceIPAddress")
        when = self.detail.get("eventTime") or self.raw.get("time", "")
        if self.name == "ConsoleLogin":
            parts = [f"{self.actor} signed in to the console"]
        else:
            parts = [f"{self.actor} called {self.name}" if self.name else self.actor]
        if ip:
            parts.append(f"from {ip}")
        if when:
            parts.append(f"at {when}")
        return " ".join(parts)


@dataclass
class Action:
    """One thing watchpost found, and what it did about it."""

    responder: str
    severity: str
    resource: str
    problem: str
    response: str  # what watchpost did, or would do in alert mode
    fixed: bool = False
    error: str = ""
    context: str = ""  # who did it, from where, when

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Settings:
    mode: str = "alert"  # "alert" only reports. "fix" also undoes the change.
    topic_arn: str = ""
    disabled: set[str] = field(default_factory=set)
    min_guardduty_severity: float = 7.0
    alert_on_root_activity: bool = True
    max_actions_per_event: int = 50
    max_notification_retries: int = 3

    @property
    def fix(self) -> bool:
        return self.mode == "fix"

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.environ.get("WATCHPOST_MODE", "alert").strip().lower()
        if mode not in ("alert", "fix"):
            raise ValueError(f"WATCHPOST_MODE must be 'alert' or 'fix', not {mode!r}")
        disabled = {d.strip() for d in os.environ.get("WATCHPOST_DISABLED", "").split(",") if d.strip()}
        return cls(
            mode=mode,
            topic_arn=os.environ.get("WATCHPOST_TOPIC_ARN", ""),
            disabled=disabled,
            min_guardduty_severity=float(os.environ.get("WATCHPOST_GUARDDUTY_MIN_SEVERITY", "7")),
            alert_on_root_activity=os.environ.get("WATCHPOST_ALERT_ON_ROOT", "true").lower() != "false",
            max_actions_per_event=int(os.environ.get("WATCHPOST_MAX_ACTIONS", "50")),
            max_notification_retries=int(os.environ.get("WATCHPOST_NOTIFY_RETRIES", "3")),
        )


class Context:
    """What a responder gets: settings, the event's region, and AWS clients."""

    def __init__(self, settings: Settings, region: str):
        self.settings = settings
        self.region = region
        self._clients: dict[str, Any] = {}

    @property
    def fix(self) -> bool:
        return self.settings.fix

    def aws(self, service: str):
        if service not in self._clients:
            self._clients[service] = boto3.client(service, region_name=self.region)
        return self._clients[service]


def has_ignore_tag(tags: Iterable[dict[str, str]] | None) -> bool:
    for tag in tags or []:
        if tag.get("Key") == IGNORE_TAG and str(tag.get("Value", "")).lower() == "true":
            return True
    return False


# ---- responder list ----

Run = Callable[[Event, Context], list[Action]]
Match = Callable[[Event], bool]


@dataclass(frozen=True)
class Responder:
    name: str
    description: str
    match: Match
    run: Run


RESPONDERS: list[Responder] = []


def responder(name: str, description: str, match: Match):
    def wrap(fn: Run) -> Run:
        if any(r.name == name for r in RESPONDERS):
            raise ValueError(f"responder {name} is defined twice")
        RESPONDERS.append(Responder(name, description, match, fn))
        return fn

    return wrap


def api_call(service: str, *names: str) -> Match:
    """Match a successful CloudTrail API call, like api_call(\"s3\", \"PutBucketAcl\")."""

    def match(event: Event) -> bool:
        return (
            event.detail_type.startswith("AWS ")
            and event.detail.get("eventSource") == f"{service}.amazonaws.com"
            and event.name in names
            and not event.failed
        )

    return match


# Remediation cooldown: prevent the same Lambda from firing repeatedly
# on the same resource within this window.  Without this, a single
# misconfiguration can trigger dozens of redundant remediations before
# the first one propagates through the AWS control plane.
REMEDIATION_COOLDOWN_SECONDS = 300  # 5 minutes

_recent_remediations: dict[str, float] = {}


def should_remediate(resource_arn: str, now: float | None = None) -> bool:
    """Check if a resource is past its remediation cooldown.

    Parameters
    ----------
    resource_arn : str
        The ARN of the resource to remediate.
    now : float, optional
        Current epoch time. Defaults to time.time().

    Returns
    -------
    bool
        True if remediation should proceed.
    """
    import time
    now = now or time.time()
    last = _recent_remediations.get(resource_arn, 0.0)
    if now - last < REMEDIATION_COOLDOWN_SECONDS:
        return False
    _recent_remediations[resource_arn] = now
    return True
