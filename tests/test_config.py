from agent_baseline_lab.config import get_path, missing_paths


def test_get_path_and_missing_paths():
    data = {"a": {"b": 1}, "x": {"empty": []}}
    assert get_path(data, "a.b") == 1
    assert get_path(data, "a.c") is None
    assert missing_paths(data, ["a.b", "a.c", "x.empty"]) == ["a.c", "x.empty"]
