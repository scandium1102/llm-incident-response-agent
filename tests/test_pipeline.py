from pathlib import Path

from src.ir_agent.pipeline import run_all


def test_pipeline_runs_all_cases(tmp_path):
    root = Path(__file__).resolve().parents[1]
    results = run_all(root / "data" / "cases", tmp_path / "outputs")
    assert len(results) >= 6
    assert all(result["evaluation"]["total_score"] >= 6 for result in results)
    assert (tmp_path / "outputs" / "json").exists()
    assert (tmp_path / "outputs" / "reports").exists()
