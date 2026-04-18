# Codex Review Fix Report

Date: 2026-03-16
Project: `C:\Users\jenxk\Desktop\ai_nidps`

## Scope

This report summarizes the code-review issues that were fixed during the 2026-03-16 remediation pass, plus the follow-up hardening work completed in the same session.

## Fixed Issues

### 1. Rollback path validation

- Restricted shadow rollback inputs to the managed `online_learning/checkpoints` tree only.
- Resolved relative checkpoint names against the managed checkpoints root.
- Rejected rollback requests when the target is missing, not a directory, outside the managed root, or missing `metadata.json`.
- Returned clearer `400` / `404` responses from the dashboard API instead of treating all rollback failures as `500`.

### 2. Admin API hardening

- Removed the previous localhost-only bypass for dangerous admin POST routes.
- Stopped trusting `X-Forwarded-For` when deciding whether a request is local.
- Added a startup-generated bootstrap admin token for local browser use when `NIDPS_ADMIN_TOKEN` is not configured.
- Added `/api/admin-bootstrap-token`, which only serves the bootstrap token to loopback clients and marks the response as `Cache-Control: no-store`.
- Kept support for explicit `NIDPS_ADMIN_TOKEN` deployments.
- Tightened default CORS behavior by removing the default `null` origin allowance.
- Kept the safer default backend bind/debug settings from the earlier pass:
  - default host `127.0.0.1`
  - debug disabled by default
  - CORS limited to local dashboard origins unless overridden by environment variables

### 3. Frontend admin request flow

- Added shared admin API helpers in `AI_NIDPS_DashBoard/src/api.js`.
- Added bootstrap-token fetch and cache logic for local dashboard sessions.
- Added automatic bootstrap-token refresh on `401` when the temporary bootstrap token becomes stale.
- Updated both dashboard implementations to use authenticated admin requests for:
  - unblock
  - shadow capture toggle
  - auto-train toggle
  - shadow checkpoint
  - shadow rollback
  - live decision source switch

### 4. Checkpoint collision prevention

- Updated shadow checkpoint naming to include microseconds, preventing same-second checkpoint overwrites during sequential training/checkpoint operations.

### 5. Safe partial label updates

- Changed label update behavior to patch only the labels present in the request.
- Prevented omitted `attack` or `malware` labels from being overwritten to `None`.
- Aligned the CLI labeling path with the same partial-update semantics.

### 6. Router unblock input validation

- Added strict IP parsing before building RouterOS unblock commands.
- Invalid IP input now returns a validation error instead of being interpolated into router commands.

### 7. Atomic writes and file locking

- Added `file_lock_utils.py` with reusable helpers for:
  - exclusive file locks
  - atomic byte writes
  - atomic text writes
- Added cross-process locking and atomic writes for:
  - online River model files
  - `control_state.json`
- Added shared model locking around shadow checkpoint creation and rollback restore so those file copies do not race model save operations.
- Switched checkpoint metadata writes to atomic writes as well.

### 8. Bad-sample training loop handling

- Detects selected samples whose features cannot be converted into trainable numeric features.
- Marks those samples as not eligible for training instead of leaving them in the ready queue forever.
- Records a rejection reason of `missing_trainable_features`.
- Returns a clear skipped-training evaluation result when a selected batch contains no trainable samples.

## Files Changed

- `dashboard_backend.py`
- `online_control.py`
- `online_models.py`
- `online_store.py`
- `online_trainer.py`
- `label_samples.py`
- `file_lock_utils.py`
- `AI_NIDPS_DashBoard/src/api.js`
- `AI_NIDPS_DashBoard/src/DashboardShell.jsx`
- `AI_NIDPS_DashBoard/src/Dashboard.jsx`

## Validation

Validation was run after the remediation changes:

- Python syntax compilation for the touched backend files
- Frontend lint
- Frontend production build

## Remaining Notes

- No project-owned automated test suite was found during this pass, so validation is currently based on static review plus syntax/lint/build checks.
- If you want stronger regression protection, the next useful step would be to add a small backend test set around:
  - admin token enforcement
  - bootstrap token behavior
  - checkpoint restore validation
  - training behavior for featureless samples

## 9. Unknown Candidate Queue And Online-Learning Hygiene

- Split unknown traffic handling into two stages:
  - capture/review
  - trainable labeled samples
- `OBS_UNKNOWN` and other heuristic-only unknown families no longer go straight into `Ready To Train`.
- Added a `candidate` sample state so unknown patterns can still be captured and reviewed without poisoning the online trainer.
- Preserved online-learning eligibility for trusted labels:
  - manual labels
  - known-rule attack/malware labels
  - trusted benign observed labels

### Benign Negative Baselines

- Added trusted benign auto-families for low-risk infrastructure traffic:
  - DHCP
  - DNS
  - NTP
- These samples can stay in the online-learning ecosystem as benign negatives instead of being misclassified as attack/malware positives.

### Policy And UI Changes

- Learning policy now treats candidate samples as review-only and keeps them out of auto-train batches.
- Dashboard model overview now reports a dedicated review queue count.
- Online Learning UI now shows:
  - pending labels
  - review candidates
  - ready-to-train samples
- `OBSERVED` actions are displayed as `Observed` instead of the more confusing `AlertOnly`.

### Data Migration Performed

- Re-ran auto-labeling against the current online sample store after the policy update.
- Existing `OBS_UNKNOWN` auto-labeled samples were demoted into the new candidate queue.
- After migration:
  - `learn_eligible=true`: `0`
  - `OBS_UNKNOWN` ready samples: `0`
  - candidate samples: `197`

### Extra Files Touched In This Follow-Up

- `nidps_monitor.py`
- `online_auto_label.py`
- `online_learning_policy.py`
- `label_samples.py`
- `AI_NIDPS_DashBoard/src/OnlineLearningPage.jsx`
