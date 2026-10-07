import asyncio
import logging
import os
import sys

import click


def _run(coro):
    """Run an async coroutine, handling event-loop edge cases."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


@click.group()
@click.option("--log-level", default=None, help="Override log level (DEBUG, INFO, WARNING, ERROR)")
@click.version_option(version="0.1.0", prog_name="aegis")
def main(log_level):
    """Aegis — Supply Chain Risk Tracker

    Two pipelines (SBOM/SCA + News Ingestion) connected by a match engine
    that turns generic threat intel into actionable, repo-specific alerts.
    """
    from aegis.config import get_settings

    settings = get_settings()
    level = log_level or settings.log_level
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# SBOM sub-group
# ---------------------------------------------------------------------------

@main.group()
def sbom():
    """SBOM / SCA pipeline — scan repos for dependencies and vulnerabilities."""


@sbom.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--repo-name", default=None, help="Override repo name (defaults to directory name)")
def scan(repo_path, repo_name):
    """Run the full SBOM pipeline (Cartograph + Auditor + Fuse + Sentinel + Licenser) on REPO_PATH."""
    from aegis.sbom.scanner import SBOMScanner

    if repo_name is None:
        repo_name = os.path.basename(os.path.abspath(repo_path))

    click.echo(f"Starting SBOM scan for '{repo_name}' at {os.path.abspath(repo_path)} ...")

    try:
        scanner = SBOMScanner()
        result = _run(scanner.scan_repo(repo_path, repo_name))
    except FileNotFoundError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        raise SystemExit(1)
    except Exception as exc:
        click.secho(f"Scan failed: {exc}", fg="red", err=True)
        raise SystemExit(1)

    click.echo()
    click.secho(f"--- SBOM Scan Complete: {repo_name} ---", bold=True)
    click.echo(f"  Components discovered : {result.get('total_components', 0)}")
    click.echo(f"  Vulnerabilities found : {result.get('vulnerabilities_found', 0)}")
    click.echo(f"  Licenses resolved     : {result.get('licenses_resolved', 0)}")


# ---------------------------------------------------------------------------
# News sub-group
# ---------------------------------------------------------------------------

@main.group()
def news():
    """News ingestion agent — fetch, filter, enrich security articles."""


@news.command("run")
def news_run():
    """Run a single cycle of the news ingestion agent."""
    from aegis.news.agent import NewsIngestionAgent

    click.echo("Running news ingestion cycle ...")

    try:
        from aegis.db.engine import get_session

        async def _news_run():
            agent = NewsIngestionAgent()
            async with get_session() as session:
                return await agent.run_once(session)

        result = _run(_news_run())
    except Exception as exc:
        click.secho(f"News ingestion failed: {exc}", fg="red", err=True)
        raise SystemExit(1)

    click.echo()
    click.secho("--- News Ingestion Complete ---", bold=True)
    click.echo(f"  Articles fetched      : {result.get('fetched', 0)}")
    click.echo(f"  After relevance filter: {result.get('after_filter', 0)}")
    click.echo(f"  After deduplication   : {result.get('after_dedup', 0)}")
    click.echo(f"  Enriched              : {result.get('enriched', 0)}")
    click.echo(f"  Supply-chain vulns    : {result.get('supply_chain_vulns', 0)}")
    click.echo(f"  Threat intel          : {result.get('threat_intel', 0)}")


@news.command("watch")
@click.option("--interval", default=None, type=int, help="Poll interval in minutes (overrides config)")
def news_watch(interval):
    """Run the news agent continuously on a polling interval."""
    from aegis.config import get_settings
    from aegis.news.agent import NewsIngestionAgent

    settings = get_settings()
    minutes = interval or settings.feed_poll_interval_minutes
    click.echo(f"Starting continuous news monitoring (every {minutes} min). Ctrl+C to stop.")

    from aegis.db.engine import _get_session_factory

    agent = NewsIngestionAgent()

    try:
        _run(agent.run_continuous(session_factory=_get_session_factory()))
    except KeyboardInterrupt:
        click.echo("\nStopped.")


# ---------------------------------------------------------------------------
# Match command
# ---------------------------------------------------------------------------

@main.command()
@click.argument("news_id", type=int)
def match(news_id):
    """Manually trigger SBOM matching for news entry NEWS_ID."""
    from sqlalchemy import select

    from aegis.db.engine import get_session
    from aegis.db.models import News
    from aegis.match.engine import MatchEngine

    async def _do_match():
        engine = MatchEngine()
        async with get_session() as session:
            stmt = select(News).where(News.id == news_id)
            row = await session.execute(stmt)
            entry = row.scalar_one_or_none()

            if entry is None:
                click.secho(f"News entry #{news_id} not found.", fg="red", err=True)
                raise SystemExit(1)

            if entry.classification != "supply_chain_vuln":
                click.secho(
                    f"News #{news_id} is classified '{entry.classification}', not 'supply_chain_vuln'. "
                    "Only supply-chain vulnerabilities trigger SBOM matching.",
                    fg="yellow", err=True,
                )
                raise SystemExit(1)

            summary = await engine.match_news_entry(
                {"id": entry.id, "affected_packages": entry.affected_packages or []},
                session,
            )

        click.echo()
        click.secho(f"--- Match Results: {entry.title} ---", bold=True)

        for category, items in summary.items():
            label = category.replace("_", " ").title()
            click.echo(f"\n  {label}: {len(items)} package(s)")
            for item in items:
                if isinstance(item, dict):
                    pkg = item.get("component_name", item.get("name", "?"))
                    ver = item.get("version_in_use", "")
                    repo = item.get("repo", "")
                    vuln = item.get("is_vulnerable", False)
                    marker = "VULNERABLE" if vuln else "ok"
                    click.echo(f"    - {repo}: {pkg}@{ver}  [{marker}]")
                else:
                    click.echo(f"    - {item}")

    _run(_do_match())


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

@main.command("init-db")
def init_db():
    """Create all database tables (idempotent)."""
    from aegis.db.engine import init_db as _init_db

    click.echo("Initializing database ...")
    try:
        _run(_init_db())
    except Exception as exc:
        click.secho(f"Database init failed: {exc}", fg="red", err=True)
        raise SystemExit(1)
    click.secho("Database initialized successfully.", fg="green")


# ---------------------------------------------------------------------------
# Demo sub-group
# ---------------------------------------------------------------------------

@main.group()
def demo():
    """Run a demo of the full Aegis pipeline using mock data (no API keys needed)."""


@demo.command("full")
@click.option("--fast", is_flag=True, help="Skip simulated delays")
def demo_full(fast):
    """Run the complete end-to-end demo: SBOM → News → Match → Validator."""
    from aegis.demo.runner import DemoRunner

    runner = DemoRunner(fast=fast)
    runner.run_full_demo()


@demo.command("sbom")
@click.option("--fast", is_flag=True, help="Skip simulated delays")
def demo_sbom(fast):
    """Demo the SBOM/SCA pipeline (Cartograph + Auditor + Fuse + Sentinel + Licenser)."""
    from aegis.demo.runner import DemoRunner

    runner = DemoRunner(fast=fast)
    runner.run_sbom_demo()


@demo.command("news")
@click.option("--fast", is_flag=True, help="Skip simulated delays")
def demo_news(fast):
    """Demo the News Ingestion Agent (fetch → filter → dedup → enrich)."""
    from aegis.demo.runner import DemoRunner

    runner = DemoRunner(fast=fast)
    runner.run_news_demo()


@demo.command("match")
@click.option("--fast", is_flag=True, help="Skip simulated delays")
def demo_match(fast):
    """Demo the Match Engine + Validator (SBOM lookup → version check → alert)."""
    from aegis.demo.runner import DemoRunner

    runner = DemoRunner(fast=fast)
    runner.run_match_demo()


# ---------------------------------------------------------------------------
# RAG sub-group
# ---------------------------------------------------------------------------

@main.group()
def rag():
    """RAG (Retrieval-Augmented Generation) — chatbot, remediation, knowledge indexing."""


@rag.command("chat")
@click.option("--demo", is_flag=True, help="Use demo mode (mock data, no API keys)")
def rag_chat(demo):
    """Start an interactive Ask Aegis chat session in the terminal."""
    from aegis.rag import get_chat_engine

    engine = get_chat_engine(demo=demo)
    click.secho("Ask Aegis — Security Chatbot", bold=True)
    if demo:
        click.secho("  (demo mode — answers from mock knowledge base)\n", fg="cyan")
    else:
        click.secho("  (production — RAG retrieval + Claude)\n", fg="green")
    click.echo("Type your question, or 'quit' to exit.\n")

    async def _chat_loop():
        while True:
            try:
                question = click.prompt(click.style("You", fg="blue"), prompt_suffix="> ")
            except (EOFError, KeyboardInterrupt):
                click.echo("\nGoodbye.")
                break
            if question.strip().lower() in ("quit", "exit", "q"):
                click.echo("Goodbye.")
                break
            result = await engine.answer(question)
            click.echo()
            click.echo(click.style("Aegis", fg="green", bold=True) + ": " + result.answer)
            if result.sources:
                click.echo()
                click.secho("  Sources:", fg="bright_black")
                for src in result.sources:
                    click.echo(f"    [{src['type']}] {src['title']} ({src.get('score', '')})")
            click.echo()

    _run(_chat_loop())


@rag.command("index")
@click.option("--demo", is_flag=True, help="Index demo data into in-memory store")
def rag_index(demo):
    """Index SBOM, news, and remediation data into the RAG vector store."""
    if demo:
        click.echo("Indexing remediation guides into in-memory vector store...")
        from aegis.rag.embedder import MockEmbedder
        from aegis.rag.ingest import index_remediation_guides
        from aegis.rag.store import InMemoryVectorStore

        embedder = MockEmbedder()
        store = InMemoryVectorStore()
        count = _run(index_remediation_guides(embedder, store))
        click.secho(f"Indexed {count} remediation guides.", fg="green")
    else:
        click.echo("Indexing into production vector store (requires GEMINI_API_KEY + Postgres)...")
        from aegis.rag.embedder import GeminiEmbedder
        from aegis.rag.ingest import index_remediation_guides
        from aegis.rag.store import PgVectorStore

        embedder = GeminiEmbedder()
        store = PgVectorStore()
        count = _run(index_remediation_guides(embedder, store))
        click.secho(f"Indexed {count} remediation guides into pgvector.", fg="green")


@demo.command("chat")
@click.option("--fast", is_flag=True, help="Skip simulated delays")
def demo_chat(fast):
    """Demo the Ask Aegis RAG chatbot with pre-built answers."""
    from aegis.rag import get_chat_engine

    engine = get_chat_engine(demo=True)
    questions = [
        "Are we affected by the latest npm supply chain attack?",
        "What are our critical vulnerabilities?",
        "What remediation steps should we take for axios?",
    ]

    click.echo()
    click.secho("Ask Aegis — Demo Chat", bold=True)
    click.secho("  Demonstrating RAG-powered security chatbot with mock data\n", fg="cyan")

    for q in questions:
        click.echo(click.style("You", fg="blue", bold=True) + f"> {q}")
        result = _run(engine.answer(q))
        click.echo()
        click.echo(click.style("Aegis", fg="green", bold=True) + f": {result.answer}")
        if result.sources:
            click.echo()
            click.secho("  Sources:", fg="bright_black")
            for src in result.sources:
                click.echo(f"    [{src['type']}] {src['title']} ({src.get('score', '')})")
        click.echo()
        if not fast:
            import time
            time.sleep(1.0)

    click.secho("Demo chat complete.", fg="green")


# ---------------------------------------------------------------------------
# Web dashboard
# ---------------------------------------------------------------------------

@main.command("web")
@click.option("--port", default=8000, type=int, help="Port to listen on")
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--demo", is_flag=True, help="Run in demo mode (mock data, no DB/API keys needed)")
@click.option("--reload", "do_reload", is_flag=True, help="Enable auto-reload for development")
def web(port, host, demo, do_reload):
    """Start the Aegis web dashboard."""
    import uvicorn

    if demo:
        os.environ["AEGIS_WEB_DEMO"] = "1"

    click.echo(f"Starting Aegis web dashboard on http://{host}:{port}")
    if demo:
        click.secho("  Demo mode: all data is simulated (no DB or API keys required)", fg="cyan")
    click.echo("  Press Ctrl+C to stop.\n")
    uvicorn.run(
        "aegis.web.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=do_reload,
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@main.command("check")
def check():
    """Verify that external dependencies (DB, Slack, tools) are reachable."""
    import shutil

    from aegis.config import get_settings

    settings = get_settings()
    ok = True

    click.secho("--- Aegis Dependency Check ---", bold=True)

    # CLI tools
    for tool, renamed in [("syft", "Cartograph"), ("trivy", "Auditor"), ("grype", "Sentinel")]:
        path = shutil.which(tool)
        if path:
            click.echo(f"  [ok]   {renamed} ({tool}): {path}")
        else:
            click.secho(f"  [MISS] {renamed} ({tool}): not found in PATH", fg="yellow")
            ok = False

    # Config keys
    for key, label in [
        ("anthropic_api_key", "Anthropic API key"),
        ("slack_bot_token", "Slack bot token"),
        ("slack_channel_id", "Slack channel ID"),
        ("database_url", "Database URL"),
    ]:
        val = getattr(settings, key, "")
        if val:
            click.echo(f"  [ok]   {label}: configured")
        else:
            click.secho(f"  [MISS] {label}: not set", fg="yellow")
            ok = False

    if ok:
        click.secho("\nAll checks passed.", fg="green")
    else:
        click.secho("\nSome dependencies are missing — see above.", fg="yellow")


if __name__ == "__main__":
    main()
