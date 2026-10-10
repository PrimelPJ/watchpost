import copy
import json
import os
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from watchpost.core import Settings
from watchpost.handler import handle

EVENTS = Path(__file__).parent.parent / "events"
REGION = "ca-central-1"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(key, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture
def aws():
    with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
        yield


def load_event(name: str, params: dict | None = None, **detail) -> dict:
    """Load a sample event and change a few fields for the test."""
    raw = copy.deepcopy(json.loads((EVENTS / f"{name}.json").read_text()))
    raw["detail"].update(detail)
    if params:
        raw["detail"].setdefault("requestParameters", {}).update(params)
    return raw


def run(raw: dict, mode: str = "fix", **settings) -> dict:
    return handle(raw, Settings(mode=mode, **settings))


def client(service: str, region: str = REGION):
    return boto3.client(service, region_name=region)
