from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict

from file_lock_utils import atomic_write_bytes, atomic_write_text, exclusive_lock
from online_models import ATTACK_ONLINE_MODEL_PATH, MALWARE_ONLINE_MODEL_PATH, MODELS_LOCK_PATH, ONLINE_LEARNING_DIR

CONTROL_STATE_PATH = ONLINE_LEARNING_DIR / "control_state.json"
CONTROL_STATE_LOCK_PATH = ONLINE_LEARNING_DIR / "control_state.json.lock"
CHECKPOINTS_DIR = ONLINE_LEARNING_DIR / "checkpoints"
MAX_CHECKPOINTS = 30


def _prune_old_checkpoints(keep: int = MAX_CHECKPOINTS) -> None:
    if keep <= 0 or not CHECKPOINTS_DIR.exists():
        return
    checkpoints = sorted([p for p in CHECKPOINTS_DIR.iterdir() if p.is_dir()], key=lambda p: p.name)
    excess = len(checkpoints) - int(keep)
    if excess <= 0:
        return
    for path in checkpoints[:excess]:
        shutil.rmtree(path, ignore_errors=True)


def _resolve_managed_checkpoint_dir(checkpoint_dir: str | Path) -> Path:
    checkpoint_ref = str(checkpoint_dir or "").strip()
    if not checkpoint_ref:
        raise ValueError("checkpoint directory is required")

    managed_root = CHECKPOINTS_DIR.resolve()
    candidate = Path(checkpoint_ref)
    if not candidate.is_absolute():
        candidate = managed_root / candidate

    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Checkpoint not found: {candidate}") from exc

    if not resolved.is_dir():
        raise ValueError(f"Checkpoint is not a directory: {resolved}")

    try:
        resolved.relative_to(managed_root)
    except ValueError as exc:
        raise ValueError(f"Checkpoint must be inside {managed_root}") from exc

    if not (resolved / "metadata.json").exists():
        raise ValueError(f"Checkpoint is missing metadata.json: {resolved}")

    return resolved


def _default_state() -> Dict[str, Any]:
    return {
        "shadowCaptureEnabled": True,
        "autoTrainEnabled": True,
        "liveDecisionSource": "production",
        "lastDecisionSourceSwitchAt": None,
        "autoTrainMinWeight": 12.0,
        "autoTrainBatchWeight": 24.0,
        "autoTrainMaxBatchSamples": 4,
        "autoTrainMinBatchSamples": 2,
        "autoCheckpointMinTrain": 50,
        "autoCheckpointMinWeight": 12.0,
        "shadowEvalMinReferenceSamples": 8,
        "lastAutoTrainAt": None,
        "lastAutoTrainCount": 0,
        "lastAutoTrainWeight": 0.0,
        "lastShadowEvalAt": None,
        "lastShadowEvalStatus": None,
        "lastShadowEvalReason": None,
        "lastShadowEvalReferenceSamples": 0,
        "lastShadowEvalBatchSamples": 0,
        "lastShadowEvalMetrics": {},
        "lastCheckpointAt": None,
        "lastCheckpointDir": None,
        "lastRollbackAt": None,
        "lastRollbackDir": None,
        "lastRollbackReason": None,
    }


def _read_control_state_unlocked() -> Dict[str, Any]:
    if not CONTROL_STATE_PATH.exists():
        return _default_state()
    try:
        payload = json.loads(CONTROL_STATE_PATH.read_text(encoding="utf-8-sig"))
    except Exception:
        return _default_state()
    state = _default_state()
    state.update({k: payload.get(k, v) for k, v in state.items()})
    return state


def _write_control_state_unlocked(state: Dict[str, Any]) -> Dict[str, Any]:
    ONLINE_LEARNING_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write_text(CONTROL_STATE_PATH, json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return state


def _update_control_state(mutator: Callable[[Dict[str, Any]], None]) -> Dict[str, Any]:
    with exclusive_lock(CONTROL_STATE_LOCK_PATH):
        state = _read_control_state_unlocked()
        mutator(state)
        return _write_control_state_unlocked(state)


def load_control_state() -> Dict[str, Any]:
    with exclusive_lock(CONTROL_STATE_LOCK_PATH):
        return _read_control_state_unlocked()


def save_control_state(state: Dict[str, Any]) -> Dict[str, Any]:
    with exclusive_lock(CONTROL_STATE_LOCK_PATH):
        return _write_control_state_unlocked(state)


def set_shadow_capture_enabled(enabled: bool) -> Dict[str, Any]:
    return _update_control_state(lambda state: state.__setitem__("shadowCaptureEnabled", bool(enabled)))


def set_auto_train_enabled(enabled: bool) -> Dict[str, Any]:
    return _update_control_state(lambda state: state.__setitem__("autoTrainEnabled", bool(enabled)))


def set_live_decision_source(source: str) -> Dict[str, Any]:
    normalized = str(source or "production").strip().lower()
    if normalized not in {"production", "shadow"}:
        raise ValueError("live decision source must be 'production' or 'shadow'")
    def mutator(state: Dict[str, Any]) -> None:
        state["liveDecisionSource"] = normalized
        state["lastDecisionSourceSwitchAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return _update_control_state(mutator)


def update_auto_train_stats(trained_count: int, trained_weight: float = 0.0) -> Dict[str, Any]:
    def mutator(state: Dict[str, Any]) -> None:
        state["lastAutoTrainAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state["lastAutoTrainCount"] = int(trained_count)
        state["lastAutoTrainWeight"] = round(float(trained_weight or 0.0), 2)

    return _update_control_state(mutator)

# ===================== 写Accepted和rejected的结果 =====================
def update_shadow_eval_stats(result: Dict[str, Any]) -> Dict[str, Any]:
    def mutator(state: Dict[str, Any]) -> None:
        state["lastShadowEvalAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state["lastShadowEvalStatus"] = str(result.get("status") or "unknown")
        state["lastShadowEvalReason"] = str(result.get("reason") or "")
        state["lastShadowEvalReferenceSamples"] = int(result.get("referenceSamples", 0) or 0)
        state["lastShadowEvalBatchSamples"] = int(result.get("batchSamples", 0) or 0)
        state["lastShadowEvalMetrics"] = result.get("metrics") or {}

    return _update_control_state(mutator)
# ===================== ENd =====================

# ===================== 保存CheckPoint =====================
def create_shadow_checkpoint() -> Dict[str, Any]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    checkpoint_dir = CHECKPOINTS_DIR / f"checkpoint_{timestamp}"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    attack_target = checkpoint_dir / ATTACK_ONLINE_MODEL_PATH.name
    malware_target = checkpoint_dir / MALWARE_ONLINE_MODEL_PATH.name

    with exclusive_lock(MODELS_LOCK_PATH):
        if ATTACK_ONLINE_MODEL_PATH.exists():
            atomic_write_bytes(attack_target, ATTACK_ONLINE_MODEL_PATH.read_bytes())
        if MALWARE_ONLINE_MODEL_PATH.exists():
            atomic_write_bytes(malware_target, MALWARE_ONLINE_MODEL_PATH.read_bytes())

    metadata = {
        "createdAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checkpointDir": str(checkpoint_dir),
        "attackModel": str(attack_target if attack_target.exists() else ATTACK_ONLINE_MODEL_PATH),
        "malwareModel": str(malware_target if malware_target.exists() else MALWARE_ONLINE_MODEL_PATH),
    }
    atomic_write_text(checkpoint_dir / "metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    _prune_old_checkpoints()

    def mutator(state: Dict[str, Any]) -> None:
        state["lastCheckpointAt"] = metadata["createdAt"]
        state["lastCheckpointDir"] = metadata["checkpointDir"]

    _update_control_state(mutator)
    return metadata
# ===================== ENd =====================

# ===================== RollBack Shadow model =====================
def restore_shadow_checkpoint(checkpoint_dir: str | Path, reason: str = "") -> Dict[str, Any]:
    checkpoint_dir = _resolve_managed_checkpoint_dir(checkpoint_dir)
    attack_source = checkpoint_dir / ATTACK_ONLINE_MODEL_PATH.name
    malware_source = checkpoint_dir / MALWARE_ONLINE_MODEL_PATH.name
    if not attack_source.exists() and not malware_source.exists():
        raise FileNotFoundError(f"No shadow model files found in checkpoint: {checkpoint_dir}")

    with exclusive_lock(MODELS_LOCK_PATH):
        if attack_source.exists():
            atomic_write_bytes(ATTACK_ONLINE_MODEL_PATH, attack_source.read_bytes())
        if malware_source.exists():
            atomic_write_bytes(MALWARE_ONLINE_MODEL_PATH, malware_source.read_bytes())

    restored_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def mutator(state: Dict[str, Any]) -> None:
        state["lastRollbackAt"] = restored_at
        state["lastRollbackDir"] = str(checkpoint_dir)
        state["lastRollbackReason"] = reason or "manual restore"

    _update_control_state(mutator)
    return {
        "restoredAt": restored_at,
        "checkpointDir": str(checkpoint_dir),
        "reason": reason or "manual restore",
    }
# ===================== End =====================