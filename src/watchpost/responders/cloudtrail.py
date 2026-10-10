"""Turn CloudTrail logging back on, and alert when a trail is deleted or weakened."""

from __future__ import annotations

from ..core import Action, Context, Event, api_call, responder


@responder(
    "cloudtrail_off",
    "Turns CloudTrail logging back on after StopLogging. Alerts on DeleteTrail and weaker trail settings.",
    api_call("cloudtrail", "StopLogging", "DeleteTrail", "UpdateTrail"),
)
def cloudtrail_off(event: Event, ctx: Context) -> list[Action]:
    trail = event.params.get("name", "")
    if not trail:
        return []
    ct = ctx.aws("cloudtrail")

    if event.name == "DeleteTrail":
        return [
            Action(
                responder="cloudtrail_off",
                severity="critical",
                resource=f"CloudTrail trail {trail}",
                problem="A trail was deleted. Attackers do this to hide what they do next.",
                response="Alert only, a deleted trail cannot be brought back. Recreate it with Terraform.",
                context=event.who_and_when(),
            )
        ]

    if event.name == "StopLogging":
        if ct.get_trail_status(Name=trail).get("IsLogging"):
            return []  # already back on
        action = Action(
            responder="cloudtrail_off",
            severity="critical",
            resource=f"CloudTrail trail {trail}",
            problem="Logging was turned off. Attackers do this to hide what they do next.",
            response="Would turn logging back on.",
            context=event.who_and_when(),
        )
        if ctx.fix:
            ct.start_logging(Name=trail)
            action.response = "Turned logging back on."
            action.fixed = True
        return [action]

    # UpdateTrail: report settings that make the trail weaker.
    trails = ct.describe_trails(trailNameList=[trail]).get("trailList", [])
    if not trails:
        return []
    weak = []
    if not trails[0].get("IsMultiRegionTrail"):
        weak.append("it only logs one region")
    if not trails[0].get("LogFileValidationEnabled"):
        weak.append("log file validation is off")
    if not weak:
        return []
    return [
        Action(
            responder="cloudtrail_off",
            severity="medium",
            resource=f"CloudTrail trail {trail}",
            problem=f"Trail settings are weaker now: {' and '.join(weak)}.",
            response="Alert only. Check the change and set it back in Terraform if it was a mistake.",
            context=event.who_and_when(),
        )
    ]
