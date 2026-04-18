from __future__ import annotations

from collections import defaultdict
from statistics import mean
from typing import Any, Dict, Iterable, List, Sequence

from online_models import predict_online_scores


EVAL_THRESHOLD = 0.5


def _num(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def as_float_features(features: dict | None) -> dict:
    cleaned: dict[str, float] = {}
    for key, value in (features or {}).items():
        try:
            cleaned[str(key)] = float(value)
        except Exception:
            continue
    return cleaned


def _score_records(models: Dict[str, Any], samples: Sequence[Any]) -> list[dict]:
    records: list[dict] = []
    for sample in samples:
        features = as_float_features(getattr(sample, "features", None))
        if not features:
            continue
        attack_score, malware_score = predict_online_scores(models, features)
        records.append(
            {
                "sample": sample,
                "attack_score": float(attack_score),
                "malware_score": float(malware_score),
            }
        )
    return records


def _safe_mean(values: Iterable[float]) -> float | None:
    values = list(values)
    if not values:
        return None
    return round(float(mean(values)), 4)


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 4)


def _family_label(sample: Any) -> str:
    return str(getattr(sample, "family_label", "") or "")


def _family_source(sample: Any) -> str:
    return str(getattr(sample, "family_source", "") or "")


def _label_source(sample: Any) -> str:
    return str(getattr(sample, "label_source", "") or "")


def _is_manual(sample: Any) -> bool:
    source = _label_source(sample)
    return bool(source) and not source.startswith("auto")


def _is_benign(sample: Any) -> bool:
    return _family_label(sample).startswith("benign.")


def _is_known_attack(sample: Any) -> bool:
    return _family_source(sample) == "known_rule" and _family_label(sample).startswith("attack.")


def _is_known_malware(sample: Any) -> bool:
    return _family_source(sample) == "known_rule" and _family_label(sample).startswith("malware.")


def _task_metrics(
    records: Sequence[dict],
    label_attr: str,
    score_key: str,
    known_positive_predicate,
) -> dict:
    positives = 0
    negatives = 0
    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0
    positive_scores: list[float] = []
    negative_scores: list[float] = []
    benign_negative_scores: list[float] = []
    benign_negative_total = 0
    benign_false_positive = 0
    known_positive_total = 0
    known_positive_hit = 0

    for record in records:
        sample = record["sample"]
        score = float(record[score_key])
        label = getattr(sample, label_attr, None)
        if label not in (0, 1):
            continue

        predicted = 1 if score >= EVAL_THRESHOLD else 0
        if label == 1:
            positives += 1
            positive_scores.append(score)
            if predicted == 1:
                true_positive += 1
            else:
                false_negative += 1
            if known_positive_predicate(sample):
                known_positive_total += 1
                if predicted == 1:
                    known_positive_hit += 1
        else:
            negatives += 1
            negative_scores.append(score)
            if predicted == 1:
                false_positive += 1
            else:
                true_negative += 1
            if _is_benign(sample):
                benign_negative_total += 1
                benign_negative_scores.append(score)
                if predicted == 1:
                    benign_false_positive += 1

    predicted_positive = true_positive + false_positive
    return {
        "positives": positives,
        "negatives": negatives,
        "precision": _rate(true_positive, predicted_positive),
        "recall": _rate(true_positive, positives),
        "falsePositiveRate": _rate(false_positive, negatives),
        "positiveScoreMean": _safe_mean(positive_scores),
        "negativeScoreMean": _safe_mean(negative_scores),
        "benignFalsePositiveRate": _rate(benign_false_positive, benign_negative_total),
        "benignNegativeScoreMean": _safe_mean(benign_negative_scores),
        "knownRecall": _rate(known_positive_hit, known_positive_total),
    }


def evaluate_models(models: Dict[str, Any], samples: Sequence[Any]) -> dict:
    records = _score_records(models, samples)
    return {
        "samples": len(records),
        "attack": _task_metrics(records, "attack_label", "attack_score", _is_known_attack),
        "malware": _task_metrics(records, "malware_label", "malware_score", _is_known_malware),
    }


def build_reference_samples(store, exclude_event_ids: set[str] | None = None, max_samples: int = 160) -> list:
    exclude_event_ids = exclude_event_ids or set()
    candidates: list[Any] = []
    per_family: defaultdict[str, int] = defaultdict(int)

    samples = list(store.iter_samples() or [])
    for sample in reversed(samples):
        if getattr(sample, "label_status", "") != "labeled":
            continue
        if getattr(sample, "event_id", "") in exclude_event_ids:
            continue
        if not as_float_features(getattr(sample, "features", None)):
            continue
        include = _is_manual(sample) or _is_benign(sample) or _family_source(sample) == "known_rule"
        if not include:
            continue
        family = _family_label(sample) or str(getattr(sample, "rule", "") or "unknown")
        if per_family[family] >= 20:
            continue
        per_family[family] += 1
        candidates.append(sample)
        if len(candidates) >= max_samples:
            break

    candidates.reverse()
    return candidates


def _worse_higher(candidate: float | None, baseline: float | None, margin: float) -> bool:
    if candidate is None or baseline is None:
        return False
    return candidate > (baseline + margin)


def _worse_lower(candidate: float | None, baseline: float | None, margin: float) -> bool:
    if candidate is None or baseline is None:
        return False
    return candidate < (baseline - margin)


def evaluate_training_candidate(
    baseline_models: Dict[str, Any],
    candidate_models: Dict[str, Any],
    reference_samples: Sequence[Any],
    batch_samples: Sequence[Any],
    min_reference_samples: int = 5,
    bootstrap_allowed: bool = False,
    cold_start_allowed: bool = False,
    cold_start_committed: int = 0,
    cold_start_target: int = 0,
) -> dict:
    baseline_reference = evaluate_models(baseline_models, reference_samples)
    candidate_reference = evaluate_models(candidate_models, reference_samples)
    baseline_batch = evaluate_models(baseline_models, batch_samples)
    candidate_batch = evaluate_models(candidate_models, batch_samples)

    accepted = True
    reasons: list[str] = []
    guard_active = int(candidate_reference.get("samples", 0) or 0) >= int(min_reference_samples or 0)

    bootstrap_used = False
    cold_start_used = False

    if guard_active:
        base_attack = baseline_reference["attack"]
        cand_attack = candidate_reference["attack"]
        base_mal = baseline_reference["malware"]
        cand_mal = candidate_reference["malware"]

        if _worse_higher(cand_attack["benignFalsePositiveRate"], base_attack["benignFalsePositiveRate"], 0.05):
            accepted = False
            reasons.append("attack benign false-positive rate increased too much")
        if _worse_higher(cand_mal["benignFalsePositiveRate"], base_mal["benignFalsePositiveRate"], 0.03):
            accepted = False
            reasons.append("malware benign false-positive rate increased too much")
        if _worse_lower(cand_attack["knownRecall"], base_attack["knownRecall"], 0.08):
            accepted = False
            reasons.append("known attack recall regressed")
        if _worse_lower(cand_mal["knownRecall"], base_mal["knownRecall"], 0.08):
            accepted = False
            reasons.append("known malware recall regressed")
        if _worse_lower(cand_attack["precision"], base_attack["precision"], 0.10) and _worse_higher(
            cand_attack["falsePositiveRate"], base_attack["falsePositiveRate"], 0.05
        ):
            accepted = False
            reasons.append("attack precision regressed while false positives increased")
        if _worse_lower(cand_mal["precision"], base_mal["precision"], 0.10) and _worse_higher(
            cand_mal["falsePositiveRate"], base_mal["falsePositiveRate"], 0.03
        ):
            accepted = False
            reasons.append("malware precision regressed while false positives increased")
    elif bootstrap_allowed:
        bootstrap_used = True
        reasons.append("bootstrap seed accepted before full reference guard")
    elif cold_start_allowed:
        cold_start_used = True
        next_total = int(cold_start_committed or 0) + len(batch_samples)
        target_total = max(int(cold_start_target or 0), next_total)
        reasons.append(
            f"cold-start seed accepted before full reference guard ({next_total}/{target_total} committed)"
        )
    else:
        accepted = False
        reasons.append("reference guard set too small; training commit skipped until enough reference samples are available")

    base_attack_batch = baseline_batch["attack"]
    cand_attack_batch = candidate_batch["attack"]
    base_mal_batch = baseline_batch["malware"]
    cand_mal_batch = candidate_batch["malware"]

    skip_batch_improvement_guard = (cold_start_used or bootstrap_used) and not guard_active

    if not skip_batch_improvement_guard:
        if _worse_lower(cand_attack_batch["positiveScoreMean"], base_attack_batch["positiveScoreMean"], 0.03):
            accepted = False
            reasons.append("batch attack confidence did not improve")
        if _worse_higher(cand_attack_batch["negativeScoreMean"], base_attack_batch["negativeScoreMean"], 0.10):
            accepted = False
            reasons.append("batch attack negatives became too hot")
        if _worse_lower(cand_mal_batch["positiveScoreMean"], base_mal_batch["positiveScoreMean"], 0.03):
            accepted = False
            reasons.append("batch malware confidence did not improve")
        if _worse_higher(cand_mal_batch["negativeScoreMean"], base_mal_batch["negativeScoreMean"], 0.08):
            accepted = False
            reasons.append("batch malware negatives became too hot")

    if bootstrap_used and accepted and reasons == ["bootstrap seed accepted before full reference guard"]:
        reason = "bootstrap seed accepted before full reference guard"
    elif cold_start_used and accepted and len(reasons) == 1 and reasons[0].startswith("cold-start seed accepted before full reference guard"):
        reason = reasons[0]
    else:
        reason = "; ".join(reasons) if reasons else "passed shadow guardrails"
    return {
        "accepted": accepted,
        "status": "accepted" if accepted else "rejected",
        "reason": reason,
        "guardActive": guard_active,
        "bootstrapUsed": bootstrap_used,
        "coldStartUsed": cold_start_used,
        "reference": {
            "baseline": baseline_reference,
            "candidate": candidate_reference,
        },
        "batch": {
            "baseline": baseline_batch,
            "candidate": candidate_batch,
        },
    }
