from agentwall.eval.reporter import render_report, has_regression
from agentwall.eval.scorer import ScenarioScore


def _s(**kw):
    base = dict(id="s", family="f", status="caught", outcome="caught",
                is_regression=False, is_false_positive=False)
    base.update(kw); return ScenarioScore(**base)


def test_render_report_has_rates_and_matrix():
    scores = [_s(id="a", family="exfil", outcome="caught"),
              _s(id="b", family="mcp", status="blind-spot", outcome="missed")]
    out = render_report(scores)
    assert "Detection rate" in out and "1/2" in out  # 1 caught of 2 attack scenarios
    assert "exfil" in out and "mcp" in out            # coverage matrix rows


def test_render_report_counts_false_positive_rate():
    scores = [_s(id="a", benign=False, outcome="caught"),
              _s(id="b", benign=True, outcome="missed", is_false_positive=True)]
    out = render_report(scores)
    assert "Detection rate: 1/1" in out          # 1 attack, caught
    assert "False-positive rate: 1/1" in out      # 1 benign, 1 FP


def test_has_regression_true_when_any_regression():
    assert has_regression([_s(), _s(is_regression=True)]) is True
    assert has_regression([_s(), _s()]) is False
