"""Private, version-pinned CSV task-definition deregistration helper.

Accepts identifiers only. It never processes CSV, starts tasks, stops services,
reads documents or invokes a payment provider. The caller verifies final state.
"""

import re

import boto3
from botocore.config import Config

ACCOUNT = "818416606421"
REGION = "us-east-2"
FUNCTION = "utils-bot-csv-validation-cleanup"


def handler(event, context):
    version = getattr(context, "function_version", "")
    expected = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}:{version}"
    if not re.fullmatch(r"[1-9][0-9]*", version) or getattr(context, "invoked_function_arn", "") != expected:
        raise ValueError("published_version_required")
    if type(event) is not dict or set(event) != {"run_id", "definitions"}:
        raise ValueError("invalid_request")
    run = event["run_id"]
    arns = event["definitions"]
    if type(run) is not str or not re.fullmatch(r"[0-9a-f]{64}", run):
        raise ValueError("invalid_run")
    if type(arns) is not list or not 1 <= len(arns) <= 2:
        raise ValueError("invalid_definitions")
    pattern = rf"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/utils-bot-csv-private-{run[:16]}-(worker|broker):([1-9][0-9]{{0,8}})"
    targets = []
    kinds = set()
    for arn in arns:
        match = re.fullmatch(pattern, arn) if type(arn) is str else None
        if not match or match[1] in kinds:
            raise ValueError("foreign_or_duplicate_definition")
        kinds.add(match[1])
        targets.append((arn, match[1]))
    client = boto3.client("ecs", region_name=REGION, config=Config(
        retries={"total_max_attempts": 1}, connect_timeout=3, read_timeout=5))
    plans = []
    # Validate the whole request before the first mutation.
    for arn, kind in targets:
        try:
            out = client.describe_task_definition(taskDefinition=arn, include=["TAGS"])
        except client.exceptions.ClientException as error:
            message = error.response.get("Error", {}).get("Message", "")
            if message not in ("Unable to describe task definition.", "Unable to describe task-definition."):
                raise ValueError("definition_observation_unknown") from None
            plans.append((arn, "ABSENT"))
            continue
        definition = out.get("taskDefinition", {})
        tags = out.get("tags", [])
        if len({tag.get("key") for tag in tags}) != len(tags):
            raise ValueError("definition_tags_invalid")
        tags = {tag.get("key"): tag.get("value") for tag in tags}
        family = f"utils-bot-csv-private-{run[:16]}-{kind}"
        state = definition.get("status")
        if (definition.get("taskDefinitionArn") != arn or definition.get("family") != family
                or tags.get("CSVPrivateRun") != run or tags.get("CSVPrivateKind") != kind
                or state not in ("ACTIVE", "INACTIVE", "DELETE_IN_PROGRESS")):
            raise ValueError("definition_ownership_mismatch")
        plans.append((arn, state))
    states = []
    for arn, state in plans:
        if state == "ACTIVE":
            # One call; unknown responses require independent caller readback.
            out = client.deregister_task_definition(taskDefinition=arn)
            definition = out.get("taskDefinition", {})
            if definition.get("taskDefinitionArn") != arn or definition.get("status") != "INACTIVE":
                raise ValueError("deregister_outcome_unknown")
            state = "INACTIVE"
        states.append({"definition": arn, "state": state})
    return {"schema": 1, "states": states}
