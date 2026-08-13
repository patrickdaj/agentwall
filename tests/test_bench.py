from bench.run_bench import assert_targets, run_bench, run_egress_bench


async def test_bench_meets_latency_and_tier2_targets(tmp_path):
    res = await run_bench(n=200, tmp_path=tmp_path)
    assert res.events == 200
    assert res.tier2_rate < 0.02
    assert_targets(res)  # raises if p95 >= 10ms or tier2 >= 2%


async def test_egress_bench_runs_and_reports_latency(tmp_path):
    r = await run_egress_bench(50, tmp_path)
    assert r.events == 50
    assert r.p95_ms >= 0.0
