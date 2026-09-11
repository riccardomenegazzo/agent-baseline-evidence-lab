# A reproducible customer handoff investigation

This is a **synthetic verification exercise**, suitable for a short CXE walkthrough. It measures no customer business outcome and makes no live Docker enforcement claim. The question is: “The signed package verifies, but is the HTML the reviewer is reading actually part of that package?”

## Agree on success

Start with a new initialized workspace and complete the dry-run:

```bash
abl init customer-review
cd customer-review
abl-trust --dry-run --scout-mode off
abl-present --json
```

The expected overall disposition is `DRY_RUN`. Handoff verification and signature verification should succeed. The customer-facing success criterion is that a reviewer can detect a report that has changed independently of the package.

## Reproduce, diagnose and recover

Run this from the workspace. It copies only the selected presentation artifacts and public verification material into a temporary directory. The original evidence and private key are left intact.

```bash
python - <<'PY'
import shutil
import tempfile
from pathlib import Path
from agent_baseline_lab.present import build_presentation

root = Path.cwd()
original = build_presentation(root)
with tempfile.TemporaryDirectory(prefix='abl-customer-review-') as temporary:
    copy = Path(temporary)
    selected = list(original.artifacts.values())
    selected.append(f'reports/{original.run_id}.customer-trust-flow.json')
    for relative in selected:
        destination = copy / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, destination)
    build_presentation(copy, run_id=original.run_id)
    print('1. Baseline: presentation verified against the signed handoff')
    page = copy / original.artifacts['flow_html']
    saved = page.read_bytes()
    page.write_bytes(saved + b'\n<p>Unverified local change</p>\n')
    try:
        build_presentation(copy, run_id=original.run_id)
    except ValueError as error:
        print('2. Changed report rejected:', error)
    else:
        raise SystemExit('Unexpected acceptance of altered presentation')
    page.write_bytes(saved)
    build_presentation(copy, run_id=original.run_id)
    print('3. Original report restored: presentation verifies again')
PY
```

The diagnosis is a mismatch between the local HTML and the exact file included in the signed handoff. Recovery restores the original bytes and repeats the same verification. Changing a status label or issuing a new signature without establishing the correct source would not resolve the customer's evidence question.

## Explain the result

The result demonstrates a support workflow: define an observable acceptance criterion, reproduce a failure safely, identify the affected layer, recover from a known source and verify the postcondition. It also demonstrates the boundary: a self-generated key provides integrity relative to that key, not a trusted organizational identity.

For a live customer pilot, agree on the runtime controls, environment and data-sharing boundary separately. Collect an actual run and record the customer-approved next action. Time to reproduce, reviewer follow-up rounds and time to close the evidence gap are useful measurements to collect, not outcomes inferred from this exercise.
