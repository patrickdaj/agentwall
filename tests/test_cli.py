from pathlib import Path

from typer.testing import CliRunner

from agentwall.cli import app

runner = CliRunner()
POLICY = Path("src/agentwall/policy/default_policy.yaml")


def test_policy_lists_rules():
    r = runner.invoke(app, ["policy", "--policy", str(POLICY)])
    assert r.exit_code == 0 and "block-secret-egress" in r.stdout


def test_status_on_empty_db(tmp_path):
    r = runner.invoke(app, ["status", "--db", str(tmp_path / "ev.db")])
    assert r.exit_code == 0 and "events: 0" in r.stdout


def test_run_check_prints_health(tmp_path):
    r = runner.invoke(app, ["run", "--workspace", str(tmp_path), "--session", "s",
                            "--db", str(tmp_path / "ev.db"), "--policy", str(POLICY), "--check"])
    assert r.exit_code == 0 and "capabilities" in r.stdout
