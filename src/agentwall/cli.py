from __future__ import annotations

from pathlib import Path

import typer
import yaml

from agentwall.adapters.docker_sandbox import DockerSandboxAdapter
from agentwall.daemon import Daemon, DaemonConfig
from agentwall.detect.tier0_rules import RulesConfig
from agentwall.provenance import ChainCorrelator
from agentwall.storage import EventStore

app = typer.Typer(help="AgentWall — runtime security plane for AI coding agents")

_DEFAULT_RULES = RulesConfig(
    sensitive_path_globs=["**/.env", "**/.env.*", "**/.ssh/*", "**/.aws/*"],
    denied_dest_domains=[], max_upload_bytes=5_000_000, entropy_threshold=7.5,
)


@app.command()
def status(db: Path = typer.Option(...)) -> None:
    store = EventStore(db)
    typer.echo(f"events: {len(store.all_events())}")
    typer.echo(f"dead_letters: {len(store.dead_letters())}")
    store.close()


@app.command()
def replay(db: Path = typer.Option(...), session: str = typer.Option(...)) -> None:
    store = EventStore(db)
    corr = ChainCorrelator()
    for e in store.all_events():
        if e.session_id != session:
            continue
        chain = corr.observe(e)
        if chain:
            typer.echo(" -> ".join(chain.steps))
    store.close()


@app.command()
def policy(policy: Path = typer.Option(...)) -> None:
    doc = yaml.safe_load(Path(policy).read_text()) or {}
    for rule in doc.get("rules", []):
        typer.echo(f"{rule['name']}: {rule['action']}")


@app.command()
def run(workspace: Path = typer.Option(...), session: str = typer.Option(...),
        db: Path = typer.Option(...), policy: Path = typer.Option(...),
        check: bool = typer.Option(False, "--check")) -> None:
    cfg = DaemonConfig(workspace=workspace, session_id=session, db_path=db,
                       policy_path=policy, rules=_DEFAULT_RULES)
    daemon = Daemon(cfg, adapter=DockerSandboxAdapter(workspace=workspace))
    if check:
        typer.echo(str(daemon.health()))
        return
    import asyncio

    async def _serve():
        await daemon.start()
        try:
            while True:
                await asyncio.sleep(1)
        finally:
            await daemon.stop()

    asyncio.run(_serve())


if __name__ == "__main__":
    app()
