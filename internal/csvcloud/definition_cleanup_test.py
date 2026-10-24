"""Offline ownership and least-authority tests for the cleanup helper."""

import copy
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch


class ProviderError(Exception):
    def __init__(self, message):
        self.response = {"Error": {"Message": message}}


class Client:
    exceptions = types.SimpleNamespace(ClientException=ProviderError)

    def __init__(self):
        self.reads, self.writes, self.data = [], [], {}

    def describe_task_definition(self, taskDefinition, include):
        self.reads.append(taskDefinition)
        value = self.data[taskDefinition]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    def deregister_task_definition(self, taskDefinition):
        self.writes.append(taskDefinition)
        return {"taskDefinition": {"taskDefinitionArn": taskDefinition, "status": "INACTIVE"}}


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        sdk = types.SimpleNamespace(client=lambda *a, **kw: self.client)
        modules = {"boto3": sdk, "botocore": types.ModuleType("botocore"),
                   "botocore.config": types.SimpleNamespace(Config=lambda **kw: kw)}
        spec = importlib.util.spec_from_file_location("cleanup_under_test", pathlib.Path(__file__).with_name("definition_cleanup.py"))
        self.module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(self.module)
        self.run_id = "a" * 64
        self.arns = [f"arn:aws:ecs:us-east-2:818416606421:task-definition/utils-bot-csv-private-{'a' * 16}-{kind}:1" for kind in ("worker", "broker")]
        for arn, kind in zip(self.arns, ("worker", "broker")):
            self.client.data[arn] = {"taskDefinition": {"taskDefinitionArn": arn, "family": arn.split("/")[1].split(":")[0], "status": "ACTIVE"}, "tags": [{"key": "CSVPrivateRun", "value": self.run_id}, {"key": "CSVPrivateKind", "value": kind}]}
        self.context = types.SimpleNamespace(function_version="1", invoked_function_arn="arn:aws:lambda:us-east-2:818416606421:function:utils-bot-csv-validation-cleanup:1")
        self.event = {"run_id": self.run_id, "definitions": self.arns}

    def test_only_owned_definitions_are_deregistered(self):
        result = self.module.handler(self.event, self.context)
        self.assertEqual(self.client.writes, self.arns)
        self.assertTrue(all(x["state"] == "INACTIVE" for x in result["states"]))

    def test_foreign_duplicate_and_malformed_requests_never_call_aws(self):
        cases = [dict(self.event, extra=True), dict(self.event, run_id="bad"),
                 dict(self.event, definitions=[]), dict(self.event, definitions=self.arns * 2),
                 dict(self.event, definitions=[self.arns[0], self.arns[0]]),
                 dict(self.event, definitions=[self.arns[0].replace("818416606421", "111111111111")]),
                 dict(self.event, definitions=[self.arns[0].replace("us-east-2", "us-east-1")]),
                 dict(self.event, definitions=["arn:aws:ecs:us-east-2:818416606421:task-definition/agent-pdf-mock:67"])]
        for event in cases:
            with self.subTest(event=event), self.assertRaises(ValueError):
                self.module.handler(event, self.context)
        self.assertEqual(self.client.reads, [])
        self.assertEqual(self.client.writes, [])

    def test_provider_ownership_drift_prevents_all_mutations(self):
        original = copy.deepcopy(self.client.data)
        for field in ("arn", "family", "run_tag", "kind_tag", "duplicate_tag", "status"):
            self.client.data = copy.deepcopy(original)
            record = self.client.data[self.arns[1]]
            if field in ("arn", "family", "status"):
                key = {"arn": "taskDefinitionArn", "family": "family", "status": "status"}[field]
                record["taskDefinition"][key] = "foreign"
            elif field == "duplicate_tag":
                record["tags"].append(record["tags"][0])
            else:
                record["tags"][0 if field == "run_tag" else 1]["value"] = "foreign"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.handler(self.event, self.context)
            self.assertEqual(self.client.writes, [])

    def test_absent_inactive_and_pending_are_idempotent(self):
        self.client.data[self.arns[0]] = ProviderError("Unable to describe task definition.")
        for state in ("INACTIVE", "DELETE_IN_PROGRESS"):
            self.client.data[self.arns[1]]["taskDefinition"]["status"] = state
            result = self.module.handler(self.event, self.context)
            self.assertEqual(result["states"][0]["state"], "ABSENT")
            self.assertEqual(result["states"][1]["state"], state)
        self.assertEqual(self.client.writes, [])

    def test_unrecognized_provider_error_is_not_absence(self):
        self.client.data[self.arns[0]] = ProviderError("provider unavailable")
        with self.assertRaisesRegex(ValueError, "observation_unknown"):
            self.module.handler(self.event, self.context)
        self.assertEqual(self.client.writes, [])

    def test_latest_and_alias_invocations_are_rejected(self):
        for version in ("$LATEST", "current", "0", ""):
            self.context.function_version = version
            with self.assertRaises(ValueError):
                self.module.handler(self.event, self.context)
        self.assertEqual(self.client.reads, [])


if __name__ == "__main__":
    unittest.main()
