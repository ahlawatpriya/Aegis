"""Slack Block Kit notifications for Aegis supply chain risk alerts."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.errors import SlackApiError

from aegis.config import get_settings

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Posts structured Block Kit messages to Slack and manages alert threads."""

    def __init__(self) -> None:
        cfg = get_settings()
        self._client = AsyncWebClient(token=cfg.slack_bot_token)
        self._channel = cfg.slack_channel_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def post_new_alert(self, news_entry: dict[str, Any]) -> str | None:
        """Post an initial alert for a news entry. Returns the thread ts."""
        blocks = self._build_alert_blocks(news_entry)
        fallback = news_entry.get("title", "New Aegis alert")
        try:
            resp = await self._client.chat_postMessage(
                channel=self._channel,
                text=fallback,
                blocks=blocks,
                unfurl_links=False,
            )
            ts: str = resp["ts"]
            logger.info("Slack alert posted — ts=%s title=%s", ts, news_entry.get("title"))
            return ts
        except SlackApiError:
            logger.exception("Failed to post Slack alert for %s", news_entry.get("url"))
            return None

    async def post_match_results(
        self, thread_ts: str, match_summary: dict[str, Any]
    ) -> None:
        """Post SBOM match results as a thread reply."""
        blocks: list[dict] = []

        for pkg_result in match_summary.get("packages", []):
            pkg_name = pkg_result.get("name", "unknown")
            status = pkg_result.get("status")

            if status == "not_found":
                blocks.append(
                    self._section(
                        f":white_check_mark: *Marked Safe* — `{pkg_name}` not found "
                        "in any SBOM. No action needed."
                    )
                )

            elif status == "found_not_vulnerable":
                repos = pkg_result.get("repos", [])
                lines = "\n".join(
                    f"• `{r['repo']}` — {pkg_name}@{r['version_in_use']}"
                    for r in repos
                )
                blocks.append(
                    self._section(
                        f":large_blue_circle: *{len(repos)} repo(s) use `{pkg_name}`*, "
                        f"none at a vulnerable version.\n{lines}"
                    )
                )

            elif status == "found_vulnerable":
                repos = pkg_result.get("repos", [])
                lines = "\n".join(
                    f"• `{r['repo']}` — {pkg_name}@{r['version_in_use']}"
                    for r in repos
                )
                blocks.append(
                    self._section(
                        f":rotating_light: *{len(repos)} potentially vulnerable "
                        f"usage(s) found:*\n{lines}\n_Spawning validation agent(s)…_"
                    )
                )

            elif status == "manual_review":
                blocks.append(
                    self._section(
                        f":warning: *Manual review needed* — version constraint for "
                        f"`{pkg_name}` is non-actionable. @appsec please check."
                    )
                )

        if not blocks:
            return

        try:
            await self._client.chat_postMessage(
                channel=self._channel,
                thread_ts=thread_ts,
                text="SBOM match results",
                blocks=blocks,
                unfurl_links=False,
            )
            logger.info("Match results posted to thread %s", thread_ts)
        except SlackApiError:
            logger.exception("Failed to post match results to thread %s", thread_ts)

    async def post_validator_status(
        self,
        thread_ts: str,
        repo: str,
        status: str,
        details: str = "",
    ) -> None:
        """Post a validator progress/result update as a thread reply."""
        emoji_map = {
            "spawned": ":rocket:",
            "running": ":hourglass_flowing_sand:",
            "completed_reachable": ":rotating_light:",
            "completed_not_reachable": ":white_check_mark:",
            "failed": ":x:",
        }
        label_map = {
            "spawned": "Validator spawned",
            "running": "Validator running",
            "completed_reachable": "REACHABLE — vulnerable code path confirmed",
            "completed_not_reachable": "Not reachable — vulnerable code path not exercised",
            "failed": "Validator failed",
        }
        emoji = emoji_map.get(status, ":grey_question:")
        label = label_map.get(status, status)
        text = f"{emoji} *{label}* for `{repo}`"
        if details:
            text += f"\n{details}"

        try:
            await self._client.chat_postMessage(
                channel=self._channel,
                thread_ts=thread_ts,
                text=text,
                blocks=[self._section(text)],
                unfurl_links=False,
            )
            logger.info("Validator status '%s' posted for repo %s", status, repo)
        except SlackApiError:
            logger.exception(
                "Failed to post validator status for repo %s in thread %s",
                repo,
                thread_ts,
            )

    # ------------------------------------------------------------------
    # Block builders
    # ------------------------------------------------------------------

    def _build_alert_blocks(self, entry: dict[str, Any]) -> list[dict]:
        score = entry.get("impact_score") or 0
        emoji = self._severity_emoji(score)
        title = entry.get("title", "Untitled")
        url = entry.get("url", "")
        summary = entry.get("summary", "")
        source = entry.get("source", "unknown")
        classification = entry.get("classification", "unknown")
        created = entry.get("created_at")
        if isinstance(created, datetime):
            ts_str = created.strftime("%Y-%m-%d %H:%M UTC")
        else:
            ts_str = str(created) if created else datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {title[:148]}",
                    "emoji": True,
                },
            },
            self._section(f"*<{url}|{title}>*" if url else f"*{title}*"),
        ]

        if summary:
            blocks.append(self._section(summary[:2900]))

        context_parts = [
            f"*Source:* {source}",
            f"*Type:* {classification}",
            f"*Impact:* {score}/10",
            f"*Time:* {ts_str}",
        ]
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": " | ".join(context_parts)}
                ],
            }
        )

        packages = entry.get("affected_packages") or []
        if packages:
            pkg_text = self._format_packages_text(packages)
            blocks.append(self._section(f"*Affected packages:*\n{pkg_text}"))

        return blocks

    @staticmethod
    def _severity_emoji(score: int) -> str:
        if score >= 9:
            return ":rotating_light:"
        if score >= 7:
            return ":red_circle:"
        if score >= 4:
            return ":large_yellow_circle:"
        return ":white_circle:"

    @staticmethod
    def _format_packages_text(packages: list[dict]) -> str:
        lines: list[str] = []
        for pkg in packages[:15]:
            name = pkg.get("name", "?")
            eco = pkg.get("ecosystem", "")
            ver = pkg.get("vulnerable_versions", "?")
            cve = pkg.get("cve_id")
            line = f"• `{name}` ({eco}) — versions: `{ver}`"
            if cve:
                line += f" — {cve}"
            lines.append(line)
        if len(packages) > 15:
            lines.append(f"_…and {len(packages) - 15} more_")
        return "\n".join(lines)

    @staticmethod
    def _section(text: str) -> dict:
        return {
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        }
