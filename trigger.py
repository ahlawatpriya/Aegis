"""ECS Fargate task spawner for reachability-analysis validators."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aegis.config import get_settings

logger = logging.getLogger(__name__)

_MAX_POLL_SECONDS = 600  # 10 minutes
_POLL_INTERVAL_SECONDS = 30


class ValidatorTrigger:
    """Spawns per-repo ECS Fargate tasks that perform reachability analysis."""

    def __init__(self) -> None:
        cfg = get_settings()
        self._cluster = cfg.ecs_cluster
        self._task_def = cfg.ecs_task_definition
        self._subnets = cfg.ecs_subnet_list
        self._security_groups = cfg.ecs_sg_list
        self._configured = bool(self._cluster and self._task_def)

        if self._configured:
            self._ecs = boto3.client(
                "ecs",
                region_name=cfg.aws_region,
                aws_access_key_id=cfg.aws_access_key_id or None,
                aws_secret_access_key=cfg.aws_secret_access_key or None,
            )
        else:
            self._ecs = None
            logger.warning(
                "ECS validator not configured (missing ecs_cluster / ecs_task_definition). "
                "Validator tasks will be skipped."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def spawn_validators(
        self,
        vulnerable_matches: list[dict[str, Any]],
        thread_ts: str,
    ) -> list[dict[str, Any]]:
        """Group matches by repo and spawn one Fargate task per repo.

        Returns a list of ``{repo, task_arn, packages}`` dicts.
        """
        if not self._configured:
            logger.info("Validator trigger skipped — ECS not configured")
            return []

        by_repo: dict[str, list[dict]] = defaultdict(list)
        for m in vulnerable_matches:
            by_repo[m["repo"]].append(m)

        results: list[dict[str, Any]] = []
        for repo, packages in by_repo.items():
            task_arn = await self._run_task(repo, packages)
            if task_arn:
                results.append(
                    {"repo": repo, "task_arn": task_arn, "packages": packages}
                )
                logger.info("Validator spawned for %s — %s", repo, task_arn)
            else:
                logger.error("Failed to spawn validator for %s", repo)

        return results

    async def check_task_status(self, task_arn: str) -> dict[str, Any]:
        """Describe a single ECS task and return a normalised status dict."""
        if not self._configured:
            return {"status": "skipped", "reason": "ECS not configured"}

        try:
            resp = await asyncio.to_thread(
                self._ecs.describe_tasks,
                cluster=self._cluster,
                tasks=[task_arn],
            )
        except (BotoCoreError, ClientError):
            logger.exception("Failed to describe ECS task %s", task_arn)
            return {"status": "failed", "reason": "AWS API error"}

        tasks = resp.get("tasks", [])
        if not tasks:
            return {"status": "failed", "reason": "Task not found"}

        task = tasks[0]
        ecs_status = task.get("lastStatus", "UNKNOWN")
        mapped = self._map_status(task)
        mapped["ecs_status"] = ecs_status
        mapped["task_arn"] = task_arn
        return mapped

    async def poll_and_report(
        self,
        spawned: list[dict[str, Any]],
        slack_notifier: Any,
        thread_ts: str,
    ) -> None:
        """Poll spawned tasks until they finish (or timeout) and post to Slack."""
        if not spawned:
            return

        pending = {s["task_arn"]: s for s in spawned}
        deadline = time.monotonic() + _MAX_POLL_SECONDS

        while pending and time.monotonic() < deadline:
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

            for arn in list(pending):
                result = await self.check_task_status(arn)
                status = result.get("status", "unknown")

                if status in ("running", "spawned"):
                    continue

                entry = pending.pop(arn)
                repo = entry["repo"]
                detail_parts = [
                    f"`{p.get('component_name', '?')}@{p.get('version_in_use', '?')}`"
                    for p in entry["packages"]
                ]
                details = "Packages checked: " + ", ".join(detail_parts)
                if result.get("reason"):
                    details += f"\n_{result['reason']}_"

                await slack_notifier.post_validator_status(
                    thread_ts=thread_ts,
                    repo=repo,
                    status=status,
                    details=details,
                )

        if pending:
            for arn, entry in pending.items():
                logger.warning(
                    "Validator for %s timed out after %ds — %s",
                    entry["repo"],
                    _MAX_POLL_SECONDS,
                    arn,
                )
                await slack_notifier.post_validator_status(
                    thread_ts=thread_ts,
                    repo=entry["repo"],
                    status="failed",
                    details=f"Timed out after {_MAX_POLL_SECONDS // 60} minutes.",
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_task(self, repo: str, packages: list[dict]) -> str | None:
        params = self._build_task_params(repo, packages)
        try:
            resp = await asyncio.to_thread(self._ecs.run_task, **params)
            tasks = resp.get("tasks", [])
            if not tasks:
                failures = resp.get("failures", [])
                logger.error("ECS run_task returned no tasks: %s", failures)
                return None
            return tasks[0]["taskArn"]
        except (BotoCoreError, ClientError):
            logger.exception("ECS run_task failed for repo %s", repo)
            return None

    def _build_task_params(
        self, repo: str, packages: list[dict]
    ) -> dict[str, Any]:
        pkg_payload = json.dumps(
            [
                {
                    "name": p.get("component_name", ""),
                    "version": p.get("version_in_use", ""),
                    "purl": p.get("purl", ""),
                    "vulnerable_versions": p.get("vulnerable_versions", ""),
                }
                for p in packages
            ]
        )

        return {
            "cluster": self._cluster,
            "taskDefinition": self._task_def,
            "launchType": "FARGATE",
            "count": 1,
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "subnets": self._subnets,
                    "securityGroups": self._security_groups,
                    "assignPublicIp": "ENABLED",
                }
            },
            "overrides": {
                "containerOverrides": [
                    {
                        "name": "aegis-validator",
                        "environment": [
                            {"name": "REPO_NAME", "value": repo},
                            {"name": "VULNERABLE_PACKAGES", "value": pkg_payload},
                        ],
                    }
                ]
            },
        }

    @staticmethod
    def _map_status(task: dict) -> dict[str, Any]:
        last = task.get("lastStatus", "")
        if last in ("PROVISIONING", "PENDING", "ACTIVATING"):
            return {"status": "spawned"}
        if last == "RUNNING":
            return {"status": "running"}
        if last == "DEPROVISIONING":
            return {"status": "running", "reason": "Shutting down"}
        if last == "STOPPED":
            containers = task.get("containers", [])
            exit_code = None
            reason = task.get("stoppedReason", "")
            for c in containers:
                exit_code = c.get("exitCode")
                if c.get("reason"):
                    reason = c["reason"]
                break

            if exit_code == 0:
                return {"status": "completed_not_reachable", "reason": reason}
            elif exit_code == 1:
                return {"status": "completed_reachable", "reason": reason}
            else:
                return {"status": "failed", "reason": reason or f"exit code {exit_code}"}

        return {"status": "failed", "reason": f"Unexpected ECS status: {last}"}
