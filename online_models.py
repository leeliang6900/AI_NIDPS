from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Dict, Tuple

from file_lock_utils import atomic_write_bytes, exclusive_lock

ONLINE_LEARNING_DIR = Path(__file__).resolve().with_name('online_learning')
ATTACK_ONLINE_MODEL_PATH = ONLINE_LEARNING_DIR / 'model_attack_online.pkl'
MALWARE_ONLINE_MODEL_PATH = ONLINE_LEARNING_DIR / 'model_malware_online.pkl'
MODELS_LOCK_PATH = ONLINE_LEARNING_DIR / '.online_models.lock'


class MissingRiverDependency(RuntimeError):
    pass


def _require_river() -> tuple[Any, Any]:
    try:
        from river import compose, linear_model, preprocessing  # type: ignore
    except ImportError as exc:
        raise MissingRiverDependency(
            "River is not installed in the project venv. Install it first, for example: "
            "venv\\Scripts\\python.exe -m pip install river"
        ) from exc
    return compose, linear_model, preprocessing


def build_attack_model() -> Any:
    compose, linear_model, preprocessing = _require_river()
    return compose.Pipeline(
        preprocessing.StandardScaler(),
        linear_model.LogisticRegression(),
    )


def build_malware_model() -> Any:
    compose, linear_model, preprocessing = _require_river()
    return compose.Pipeline(
        preprocessing.StandardScaler(),
        linear_model.LogisticRegression(),
    )


def _save_model_unlocked(model: Any, path: Path) -> None:
    atomic_write_bytes(path, pickle.dumps(model))


def _load_or_build_unlocked(path: Path, builder) -> Any:
    if path.exists():
        with path.open('rb') as fh:
            return pickle.load(fh)
    model = builder()
    _save_model_unlocked(model, path)
    return model


def load_online_models() -> Dict[str, Any]:
    with exclusive_lock(MODELS_LOCK_PATH):
        return {
            'attack': _load_or_build_unlocked(ATTACK_ONLINE_MODEL_PATH, build_attack_model),
            'malware': _load_or_build_unlocked(MALWARE_ONLINE_MODEL_PATH, build_malware_model),
        }


def save_model(model: Any, path: Path) -> None:
    with exclusive_lock(MODELS_LOCK_PATH):
        _save_model_unlocked(model, path)


def save_online_models(models: Dict[str, Any]) -> None:
    with exclusive_lock(MODELS_LOCK_PATH):
        _save_model_unlocked(models['attack'], ATTACK_ONLINE_MODEL_PATH)
        _save_model_unlocked(models['malware'], MALWARE_ONLINE_MODEL_PATH)


def predict_online_scores(models: Dict[str, Any], features: Dict[str, float]) -> Tuple[float, float]:
    attack_scores = models['attack'].predict_proba_one(features) or {}
    malware_scores = models['malware'].predict_proba_one(features) or {}
    return float(attack_scores.get(True, 0.0)), float(malware_scores.get(True, 0.0))


def learn_online(
    models: Dict[str, Any],
    features: Dict[str, float],
    attack_label: int | None,
    malware_label: int | None,
) -> None:
    if attack_label is not None:
        models['attack'].learn_one(features, bool(attack_label))
    if malware_label is not None:
        models['malware'].learn_one(features, bool(malware_label))
