import argparse
import json
import sys
from pathlib import Path

from evaluation import report, runner
from evaluation.build_dataset import main as build_main

HERE = Path(__file__).parent
ROOT = HERE.parent
BASELINE = HERE / "baseline.json"
FIRST = HERE / "first_measurement.json"
KEYS = ("recall_by_category", "recall_by_category_origin", "recall_by_technique", "benign", "recall_all_bad",
        "missed_ids", "false_positive_ids", "exposed_after_release", "actions_on_bad", "n_cases")


def stable(summaries: dict) -> dict:
    return {s: {k: summaries[s][k] for k in KEYS} for s in summaries}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evaluation")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    r = sub.add_parser("run")
    r.add_argument("--update-baseline", action="store_true")
    r.add_argument("--save-first", action="store_true", help="record this run as the first measurement (do once)")
    r.add_argument("--no-perf", action="store_true")
    r.add_argument("--show-misses", choices=["dev", "none"], default="none",
                   help="print missed and wrongly-changed cases of the DEV split only")
    sub.add_parser("check")
    a = ap.parse_args(argv)

    if a.cmd == "build":
        build_main()
        return 0
    res = runner.evaluate()
    s = res["summaries"]
    if a.cmd == "check":
        base = json.loads(BASELINE.read_text(encoding="utf-8"))
        now = json.loads(json.dumps(stable(s)))
        if now == base:
            print("OK: results match evaluation/baseline.json")
            return 0
        print("DIFFERENT from evaluation/baseline.json. If the change is intended, run: python -m evaluation run --update-baseline")
        return 1
    for name in ("all", "dev", "heldout"):
        x = s[name]
        print(f"{name:8s} n={x['n_cases']:4d}  bad handled {x['recall_all_bad']['ok']}/{x['recall_all_bad']['n']}"
              f"  normal wrongly changed {x['benign']['false_positives']}/{x['benign']['n']}")
    if a.show_misses == "dev":
        cases = {c.id: c for c in res["cases"]}
        for i in s["dev"]["missed_ids"] + s["dev"]["false_positive_ids"]:
            print("  ", i, cases[i].technique, res["outcomes"][i].action, repr(cases[i].text[:100]))
    if a.save_first:
        if FIRST.exists():
            print("first_measurement.json already exists; not overwritten")
        else:
            FIRST.write_text(json.dumps(stable(s), indent=1, sort_keys=True), encoding="utf-8")
    if a.update_baseline:
        BASELINE.write_text(json.dumps(stable(s), indent=1, sort_keys=True), encoding="utf-8")
        print("baseline updated")
    perf = worst = None
    if not a.no_perf:
        perf, worst = runner.benchmark(), runner.worst_case_timing()
    first = json.loads(FIRST.read_text(encoding="utf-8")) if FIRST.exists() else None
    (HERE / "results.json").write_text(json.dumps({**runner.as_json(res), "performance": perf, "worst_case": worst},
                                                  indent=1, sort_keys=True), encoding="utf-8")
    (ROOT / "docs" / "evaluation_results.md").write_text(report.render(s, perf, worst, first), encoding="utf-8")
    print("wrote evaluation/results.json and docs/evaluation_results.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
