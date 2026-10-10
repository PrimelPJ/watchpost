import importlib
import inspect
import json
import pkgutil

import boto3
import pytest

import watchpost.responders
from watchpost.core import RESPONDERS, Action, Event
from watchpost.handler import WatchpostError, format_alert, lambda_handler

from .conftest import EVENTS, load_event, run


def test_unrelated_event_does_nothing(aws):
    raw = load_event("sg-ssh-open", eventName="DescribeInstances")
    assert run(raw) == {"mode": "fix", "matched": [], "actions": []}


def test_every_sample_event_matches_exactly_one_responder():
    for path in EVENTS.glob("*.json"):
        event = Event(json.loads(path.read_text()))
        matched = [r.name for r in RESPONDERS if r.match(event)]
        assert len(matched) == 1, f"{path.name} matched {matched}"


def test_disabled_responder(aws):
    assert run(load_event("root-console-login"), disabled={"root_activity"})["matched"] == []


def test_mode_comes_from_env(aws, monkeypatch):
    monkeypatch.setenv("WATCHPOST_MODE", "alert")
    assert lambda_handler(load_event("root-console-login"))["mode"] == "alert"
    monkeypatch.setenv("WATCHPOST_MODE", "yolo")
    with pytest.raises(ValueError):
        lambda_handler(load_event("root-console-login"))


def test_failure_is_reported_then_raised(aws):
    # The security group does not exist, so the responder fails.
    with pytest.raises(WatchpostError) as err:
        run(load_event("sg-ssh-open"))
    result = json.loads(str(err.value))
    assert result["actions"][0]["error"]
    assert "by hand" in result["actions"][0]["response"]


def test_alerts_go_to_sns(aws):
    sns = boto3.client("sns", region_name="us-east-1")
    topic = sns.create_topic(Name="watchpost")["TopicArn"]
    sqs = boto3.client("sqs", region_name="us-east-1")
    queue = sqs.create_queue(QueueName="inbox")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)

    run(load_event("root-console-login"), topic_arn=topic)
    messages = sqs.receive_message(QueueUrl=queue)["Messages"]
    body = json.loads(messages[0]["Body"])
    assert body["Subject"].startswith("watchpost CRITICAL")
    assert "What watchpost did:" in body["Message"]


def test_long_subject_is_cut_to_sns_limit():
    action = Action("x", "high", "r", "a" * 200, "did a thing")
    subject, _ = format_alert(action, "fix", Event({}))
    assert len(subject) == 100


def test_no_em_dashes_in_alert_text():
    for mod in pkgutil.iter_modules(watchpost.responders.__path__):
        source = inspect.getsource(importlib.import_module(f"watchpost.responders.{mod.name}"))
        assert chr(0x2014) not in source, mod.name
