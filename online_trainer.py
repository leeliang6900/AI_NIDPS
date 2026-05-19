from __future__ import annotations

import argparse
import pickle
from typing import Any, Dict, List

from online_learning_policy import (
    MAX_REJECT_RETRIES,
    apply_learning_policy,
    build_family_variant_signature,
    build_learning_signature,
    is_trusted_auto_label,
    prune_redundant_learning_samples,
)
from online_control import create_shadow_checkpoint, restore_shadow_checkpoint, update_shadow_eval_stats
from online_evaluator import build_reference_samples, evaluate_training_candidate
from online_models import MissingRiverDependency, learn_online, load_online_models, save_online_models
from online_schema import OnlineSample
from online_store import OnlineSampleStore


STORE = OnlineSampleStore()
BOOTSTRAP_SEED_FAMILIES = 3
COLD_START_SEED_TARGET = 24
TRUSTED_COLD_START_CONFIDENCE = {"high", "medium"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Train the River shadow online models from labeled online samples.'
    )
    parser.add_argument('--limit', type=int, default=0, help='Maximum number of labeled-but-untrained samples to consume. 0 means all.')
    parser.add_argument('--checkpoint', action='store_true', help='Create a shadow checkpoint after training succeeds.')
    return parser.parse_args()


def as_float_features(features: dict) -> dict:
    cleaned = {}
    for key, value in (features or {}).items():
        try:
            cleaned[str(key)] = float(value)
        except Exception:
            continue
    return cleaned


def clone_models(models: Dict[str, Any]) -> Dict[str, Any]:
    return pickle.loads(pickle.dumps(models))


def sample_priority(sample: OnlineSample) -> tuple:
    label_source = str(sample.label_source or '')
    learn_reason = str(getattr(sample, 'learn_reason', '') or '')
    manual_rank = 0 if label_source and not label_source.startswith('auto') else 1
    reason_rank = {
        'manual_label': 0,
        'novel_pattern': 1,
        'stable_family_seed': 1,
        'stable_family_recalibration': 2,
        'novel_variant_followup': 2,
        'candidate_pattern': 3,
        'stable_family_followup': 4,
        'stable_known_family': 4,
        'candidate_followup': 5,
        'retry_after_failed_train': 6,
    }.get(learn_reason, 5)
    novelty = float(getattr(sample, 'novelty_score', 0.0) or 0.0)
    weight = float(getattr(sample, 'learn_weight', 0.0) or 0.0)
    ts = str(sample.ts or '')
    return (manual_rank, reason_rank, -weight, -novelty, ts)


def _family_identity(sample: OnlineSample) -> str:
    return str(getattr(sample, 'family_label', None) or sample.rule or sample.category or 'unknown').strip().lower()


def _trained_family_counts(samples: List[OnlineSample]) -> dict[str, int]:
    family_counts: dict[str, int] = {}
    for sample in samples:
        if not sample.trained:
            continue
        family = _family_identity(sample)
        family_counts[family] = family_counts.get(family, 0) + 1
    return family_counts


def _selection_priority(sample: OnlineSample, trained_families: dict[str, int]) -> tuple:
    family_seed_rank = 0 if trained_families.get(_family_identity(sample), 0) <= 0 else 1
    attempt_rank = 0 if int(getattr(sample, 'train_attempt_count', 0) or 0) <= 0 else 1
    return (family_seed_rank, attempt_rank, *sample_priority(sample))


def _is_first_family_seed_sample(sample: OnlineSample, trained_families: dict[str, int]) -> bool:
    return trained_families.get(_family_identity(sample), 0) <= 0


def _is_trusted_cold_start_sample(sample: OnlineSample) -> bool:
    if getattr(sample, "attack_label", None) is None and getattr(sample, "malware_label", None) is None:
        return False
    family_source = str(getattr(sample, "family_source", "") or "").strip()
    family_label = str(getattr(sample, "family_label", "") or "").strip()
    label_source = getattr(sample, "label_source", None)
    if not is_trusted_auto_label(label_source, family_source, family_label):
        return False
    family_confidence = str(getattr(sample, "family_confidence", "") or "").strip().lower()
    if family_confidence and family_confidence not in TRUSTED_COLD_START_CONFIDENCE:
        return False
    return True


def _trained_cold_start_seed_count(samples: List[OnlineSample]) -> int:
    return sum(1 for sample in samples if sample.trained and _is_trusted_cold_start_sample(sample))


def _trained_signature_counts(samples: List[OnlineSample]) -> tuple[dict[str, int], dict[str, int]]:
    signature_counts: dict[str, int] = {}
    variant_counts: dict[str, int] = {}
    for sample in samples:
        if not sample.trained:
            continue
        signature = str(getattr(sample, 'learn_signature', None) or build_learning_signature(sample))
        variant_signature = build_family_variant_signature(sample)
        signature_counts[signature] = signature_counts.get(signature, 0) + 1
        variant_counts[variant_signature] = variant_counts.get(variant_signature, 0) + 1
    return signature_counts, variant_counts


def refresh_learning_state() -> List[OnlineSample]:
    all_samples = STORE.list_samples()
    changed = False
    if apply_learning_policy(all_samples):
        changed = True
    pruned_samples = prune_redundant_learning_samples(all_samples)
    if len(pruned_samples) != len(all_samples):
        all_samples = pruned_samples
        changed = True
    if changed:
        STORE.rewrite_preserving_new_samples(all_samples)
    return all_samples


def _should_train_now(
    sample: OnlineSample,
    trained_signatures: dict[str, int],
    trained_variants: dict[str, int],
    selected_signatures: set[str],
    selected_variants: set[str],
) -> bool:
    signature = str(getattr(sample, 'learn_signature', None) or build_learning_signature(sample))
    variant_signature = build_family_variant_signature(sample)
    reason = str(getattr(sample, 'learn_reason', '') or '')
    label_source = str(sample.label_source or '')
    manual_label = bool(label_source) and not label_source.startswith('auto')

    if not signature:
        return False
    if not bool(getattr(sample, 'learn_eligible', False)):
        return False
    if int(getattr(sample, 'reject_count', 0) or 0) >= MAX_REJECT_RETRIES and int(getattr(sample, 'train_attempt_count', 0) or 0) > 0:
        return False
    if signature in selected_signatures or variant_signature in selected_variants:
        return False

    always_allow = {
        'manual_label',
        'novel_pattern',
        'novel_variant_followup',
        'stable_family_seed',
        'stable_family_recalibration',
        'candidate_pattern',
        'retry_after_failed_train',
    }
    if manual_label or reason in always_allow:
        return True

    if reason in {'stable_family_followup', 'stable_known_family', 'candidate_followup'}:
        return trained_variants.get(variant_signature, 0) <= 0 and trained_signatures.get(signature, 0) <= 0

    return trained_variants.get(variant_signature, 0) <= 0 and trained_signatures.get(signature, 0) <= 0

# ===================== 列出可以训练的样本 =====================
def list_distinct_trainable_samples() -> List[OnlineSample]:
    all_samples = refresh_learning_state()
    trained_families = _trained_family_counts(all_samples)
    ready_samples = sorted(
        [
            sample
            for sample in all_samples
            if sample.label_status == 'labeled'
            and not sample.trained
            and bool(getattr(sample, 'learn_eligible', False))
        ],
        key=lambda sample: _selection_priority(sample, trained_families),
    )
    trained_signatures, trained_variants = _trained_signature_counts(all_samples)
    selected_signatures: set[str] = set()
    selected_variants: set[str] = set()
    selected: list[OnlineSample] = []

    for sample in ready_samples:
        if not _should_train_now(sample, trained_signatures, trained_variants, selected_signatures, selected_variants):
            continue
        signature = str(getattr(sample, 'learn_signature', None) or build_learning_signature(sample))
        variant_signature = build_family_variant_signature(sample)
        selected.append(sample)
        selected_signatures.add(signature)
        selected_variants.add(variant_signature)

    return selected
# ===================== End =====================

# ===================== 选要训练的样本 =====================
def select_samples(limit: int, max_weight: float = 0.0, max_samples: int = 0, min_samples: int = 1) -> List[OnlineSample]:
    samples = list_distinct_trainable_samples()
    if limit > 0:
        return samples[:limit]
    if max_weight <= 0 and max_samples <= 0:
        return samples

    selected: list[OnlineSample] = []
    total_weight = 0.0
    for sample in samples:
        sample_weight = float(getattr(sample, 'learn_weight', 0.0) or 0.0)
        if max_samples > 0 and len(selected) >= max_samples:
            break
        if selected and max_weight > 0 and (total_weight + sample_weight) > max_weight and len(selected) >= max(int(min_samples or 1), 1):
            break
        selected.append(sample)
        total_weight += sample_weight
    return selected
# ===================== END =====================

# ===================== 最后可单样本训练的样本 =====================
def can_auto_train_single_tail_sample(samples: List[OnlineSample]) -> bool:
    if len(samples) != 1:
        return False
    sample = samples[0]
    return (
        bool(getattr(sample, 'learn_eligible', False))
        and not bool(getattr(sample, 'trained', False))
        and int(getattr(sample, 'train_attempt_count', 0) or 0) <= 0
        and int(getattr(sample, 'reject_count', 0) or 0) <= 0
        and float(getattr(sample, 'learn_weight', 0.0) or 0.0) > 0.0
    )
# ===================== END =====================

# ===================== Shadow Training的主逻辑 =====================
def train_samples(samples: List[OnlineSample], checkpoint: bool = False, min_reference_samples: int = 5) -> Dict[str, object]:
    if not samples:
        empty_eval = {
            'status': 'skipped',
            'reason': 'no ready samples',
            'referenceSamples': 0,
            'batchSamples': 0,
            'metrics': {},
        }
        update_shadow_eval_stats(empty_eval)
        return {
            'trained': 0,
            'attack_positive': 0,
            'malware_positive': 0,
            'trained_weight': 0.0,
            'accepted': False,
            'preCheckpoint': None,
            'postCheckpoint': None,
            'evaluation': empty_eval,
        }

    try:
        baseline_models = load_online_models()
    except MissingRiverDependency as exc:
        raise RuntimeError(str(exc)) from exc

    pre_checkpoint = None
    candidate_models = clone_models(baseline_models)
    all_samples = STORE.list_samples()
    trained_families = _trained_family_counts(all_samples)
    bootstrap_allowed = (
        bool(samples)
        and len(trained_families) < BOOTSTRAP_SEED_FAMILIES
        and all(_is_first_family_seed_sample(sample, trained_families) for sample in samples)
    )
    trained_cold_start_seeds = _trained_cold_start_seed_count(all_samples)
    cold_start_allowed = (
        bool(samples)
        and trained_cold_start_seeds < COLD_START_SEED_TARGET
        and all(_is_trusted_cold_start_sample(sample) for sample in samples)
    )
    reference_samples = build_reference_samples(
        STORE,
        exclude_event_ids={sample.event_id for sample in samples},
    )

    trained_features = 0
    attack_positive = 0
    malware_positive = 0
    trained_weight = 0.0
    trained_ids: list[str] = []
    skipped_feature_ids: list[str] = []

    for sample in samples:
        features = as_float_features(sample.features)
        if not features:
            skipped_feature_ids.append(sample.event_id)
            continue
        learn_online(candidate_models, features, sample.attack_label, sample.malware_label)
        trained_features += 1
        attack_positive += int(sample.attack_label or 0)
        malware_positive += int(sample.malware_label or 0)
        trained_weight += float(getattr(sample, 'learn_weight', 0.0) or 0.0)
        trained_ids.append(sample.event_id)

    if skipped_feature_ids:
        STORE.mark_untrainable_batch(skipped_feature_ids, reason='missing_trainable_features')

    if trained_ids:
        STORE.mark_training_attempt_batch(trained_ids)

    if trained_features <= 0:
        empty_eval = {
            'status': 'skipped',
            'reason': 'selected samples are missing trainable features',
            'referenceSamples': len(reference_samples),
            'batchSamples': 0,
            'metrics': {},
        }
        update_shadow_eval_stats(empty_eval)
        return {
            'trained': 0,
            'attack_positive': 0,
            'malware_positive': 0,
            'trained_weight': 0.0,
            'accepted': False,
            'preCheckpoint': None,
            'postCheckpoint': None,
            'evaluation': empty_eval,
        }

    evaluation = evaluate_training_candidate(
        baseline_models,
        candidate_models,
        reference_samples,
        samples,
        min_reference_samples=min_reference_samples,
        bootstrap_allowed=bootstrap_allowed,
        cold_start_allowed=cold_start_allowed,
        cold_start_committed=trained_cold_start_seeds,
        cold_start_target=COLD_START_SEED_TARGET,
    )
    evaluation_payload = {
        'status': evaluation['status'],
        'reason': evaluation['reason'],
        'referenceSamples': int(evaluation['reference']['candidate'].get('samples', 0) or 0),
        'batchSamples': int(evaluation['batch']['candidate'].get('samples', 0) or 0),
        'metrics': {
            'guardActive': bool(evaluation.get('guardActive', False)),
            'coldStartUsed': bool(evaluation.get('coldStartUsed', False)),
            'reference': evaluation['reference'],
            'batch': evaluation['batch'],
        },
    }

    update_shadow_eval_stats(evaluation_payload)

    if not evaluation.get('accepted', False):
        STORE.mark_rejected_batch(
            trained_ids,
            evaluation_payload.get('reason', ''),
            max_retries=MAX_REJECT_RETRIES,
        )
        return {
            'trained': 0,
            'attack_positive': attack_positive,
            'malware_positive': malware_positive,
            'trained_weight': round(trained_weight, 2),
            'accepted': False,
            'preCheckpoint': pre_checkpoint,
            'postCheckpoint': None,
            'evaluation': evaluation_payload,
        }

    post_checkpoint = None
    try:
        pre_checkpoint = create_shadow_checkpoint()
        save_online_models(candidate_models)
        STORE.mark_trained_batch(trained_ids)
        if checkpoint:
            post_checkpoint = create_shadow_checkpoint()
    except Exception as exc:
        if pre_checkpoint:
            restore_shadow_checkpoint(pre_checkpoint['checkpointDir'], reason=f'auto rollback after failed save: {exc}')
        raise

    return {
        'trained': trained_features,
        'attack_positive': attack_positive,
        'malware_positive': malware_positive,
        'trained_weight': round(trained_weight, 2),
        'accepted': True,
        'preCheckpoint': pre_checkpoint,
        'postCheckpoint': post_checkpoint,
        'evaluation': evaluation_payload,
    }
# ===================== END =====================

# ===================== 从Ready queue触发训练  =====================
def train_ready_samples(
    limit: int = 0,
    checkpoint: bool = False,
    max_weight: float = 0.0,
    max_samples: int = 0,
    min_reference_samples: int = 5,
    min_samples: int = 1,
) -> Dict[str, object]:
    available_ready = list_distinct_trainable_samples()
    tail_batch_allowed = can_auto_train_single_tail_sample(available_ready)
    effective_min_samples = 1 if tail_batch_allowed else max(int(min_samples or 1), 1)
    samples = select_samples(limit, max_weight=max_weight, max_samples=max_samples, min_samples=effective_min_samples)
    if not samples or len(samples) < effective_min_samples:
        return {
            'trained': 0,
            'attack_positive': 0,
            'malware_positive': 0,
            'trained_weight': 0.0,
            'accepted': False,
            'preCheckpoint': None,
            'postCheckpoint': None,
            'evaluation': {
                'status': 'skipped',
                'reason': 'not enough ready samples for the next safe micro-batch',
                'referenceSamples': 0,
                'batchSamples': len(samples),
                'metrics': {},
            },
        }

    return train_samples(samples, checkpoint=checkpoint, min_reference_samples=min_reference_samples)
# ===================== END =====================

def main() -> None:
    args = parse_args()
    try:
        result = train_ready_samples(args.limit, args.checkpoint)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    if result['trained'] == 0:
        print(f"No training committed. {result.get('evaluation', {}).get('reason', 'No labeled online samples are ready for training.')}")
        return

    print(f"Trained shadow models on {result['trained']} sample(s).")
    print(f"Attack positive labels: {result['attack_positive']}")
    print(f"Malware positive labels: {result['malware_positive']}")
    print(f"Training weight consumed: {result.get('trained_weight', 0.0)}")
    print(f"Evaluation: {result.get('evaluation', {}).get('status', 'unknown')} - {result.get('evaluation', {}).get('reason', '-')}")
    pre_metadata = result.get('preCheckpoint')
    if pre_metadata:
        print(f"Pre-train checkpoint: {pre_metadata['checkpointDir']}")
    post_metadata = result.get('postCheckpoint')
    if post_metadata:
        print(f"Post-train checkpoint: {post_metadata['checkpointDir']}")


if __name__ == '__main__':
    main()
