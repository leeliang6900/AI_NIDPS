from __future__ import annotations

import argparse
from typing import Any

import bootstrap_online_models
import train_ai
import train_malware
from online_control import create_shadow_checkpoint, load_control_state, save_control_state
from online_learning_policy import apply_learning_policy, prune_redundant_learning_samples
from online_models import MissingRiverDependency, build_attack_model, build_malware_model, save_online_models
from online_store import OnlineSampleStore


STORE = OnlineSampleStore()
RECOMMENDED_STATE = {
    "autoTrainMinWeight": 24.0,
    "autoTrainBatchWeight": 36.0,
    "autoTrainMaxBatchSamples": 4,
    "autoTrainMinBatchSamples": 3,
    "shadowEvalMinReferenceSamples": 8,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bootstrap the River shadow models, apply safer online-training defaults, and thaw rejected online samples."
    )
    parser.add_argument("--attack-epochs", type=int, default=2, help="How many bootstrap passes to run for the attack online model.")
    parser.add_argument("--malware-epochs", type=int, default=2, help="How many bootstrap passes to run for the malware online model.")
    parser.add_argument("--skip-bootstrap", action="store_true", help="Keep the current River shadow model files and skip bootstrap.")
    parser.add_argument("--skip-thaw", action="store_true", help="Do not reset retry-limited samples back into the policy queue.")
    parser.add_argument("--skip-defaults", action="store_true", help="Do not apply the safer auto-train control-state defaults.")
    parser.add_argument("--skip-checkpoint", action="store_true", help="Do not create a pre-change checkpoint.")
    return parser.parse_args()


def bootstrap_shadow_models(attack_epochs: int, malware_epochs: int) -> dict[str, Any]:
    try:
        attack_model = build_attack_model()
        malware_model = build_malware_model()
    except MissingRiverDependency as exc:
        raise RuntimeError(str(exc)) from exc

    print("Loading UNSW training data for River bootstrap...")
    df = bootstrap_online_models.load_unsw_dataframe()
    print(f"Loaded rows: {len(df)}")

    print("Building attack bootstrap dataset...")
    attack_X, attack_y = bootstrap_online_models.build_attack_bootstrap_dataset(df)
    print(f"Attack windows: {len(attack_X)} | positives: {int(attack_y.sum())}")

    print("Building malware bootstrap dataset...")
    malware_X, malware_y = bootstrap_online_models.build_malware_bootstrap_dataset(df)
    print(f"Malware windows: {len(malware_X)} | positives: {int(malware_y.sum())}")

    print(f"Bootstrapping attack model for {attack_epochs} epoch(s)...")
    bootstrap_online_models.bootstrap_binary_model(
        attack_model,
        attack_X,
        attack_y,
        max(int(attack_epochs or 1), 1),
        train_ai.RANDOM_STATE,
    )

    print(f"Bootstrapping malware model for {malware_epochs} epoch(s)...")
    bootstrap_online_models.bootstrap_binary_model(
        malware_model,
        malware_X,
        malware_y,
        max(int(malware_epochs or 1), 1),
        train_malware.RANDOM_STATE,
    )

    save_online_models({"attack": attack_model, "malware": malware_model})
    return {
        "attackWindows": int(len(attack_X)),
        "attackPositives": int(attack_y.sum()),
        "malwareWindows": int(len(malware_X)),
        "malwarePositives": int(malware_y.sum()),
    }


def apply_recommended_defaults() -> dict[str, Any]:
    state = load_control_state()
    state.update(RECOMMENDED_STATE)
    return save_control_state(state)


def thaw_rejected_samples() -> dict[str, int]:
    samples = STORE.list_samples()
    thawed = 0

    for sample in samples:
        if sample.trained:
            continue
        if sample.label_status != "labeled":
            continue
        reject_count = int(getattr(sample, "reject_count", 0) or 0)
        learn_reason = str(getattr(sample, "learn_reason", "") or "")
        if reject_count <= 0 and learn_reason != "retry_limit_reached":
            continue
        sample.learn_eligible = True
        sample.learn_weight = 0.0
        sample.learn_reason = "awaiting_policy_refresh"
        sample.learn_signature = None
        sample.reject_count = 0
        sample.train_attempt_count = 0
        sample.last_train_attempt_at = None
        sample.last_rejected_at = None
        sample.last_reject_reason = None
        thawed += 1

    changed = thawed > 0
    if apply_learning_policy(samples):
        changed = True

    pruned_samples = prune_redundant_learning_samples(samples)
    if len(pruned_samples) != len(samples):
        changed = True
    samples = pruned_samples

    if changed:
        STORE.rewrite_preserving_new_samples(samples)

    ready = 0
    review = 0
    pending = 0
    trained = 0
    for sample in samples:
        if sample.trained:
            trained += 1
        elif sample.label_status == "candidate":
            review += 1
        elif sample.label_status == "pending":
            pending += 1
        elif sample.label_status == "labeled" and bool(getattr(sample, "learn_eligible", False)):
            ready += 1

    return {
        "thawed": thawed,
        "ready": ready,
        "review": review,
        "pending": pending,
        "trained": trained,
        "total": len(samples),
    }


def main() -> None:
    args = parse_args()
    checkpoint = None
    if not args.skip_checkpoint:
        checkpoint = create_shadow_checkpoint()
        print(f"Pre-change checkpoint: {checkpoint['checkpointDir']}")

    if not args.skip_defaults:
        state = apply_recommended_defaults()
        print(
            "Applied safer defaults: "
            f"minWeight={state['autoTrainMinWeight']} "
            f"batchWeight={state['autoTrainBatchWeight']} "
            f"maxBatch={state['autoTrainMaxBatchSamples']} "
            f"minBatch={state['autoTrainMinBatchSamples']} "
            f"minReference={state['shadowEvalMinReferenceSamples']}"
        )

    if not args.skip_bootstrap:
        summary = bootstrap_shadow_models(args.attack_epochs, args.malware_epochs)
        print(
            "Bootstrap complete: "
            f"attack_windows={summary['attackWindows']} "
            f"attack_positives={summary['attackPositives']} "
            f"malware_windows={summary['malwareWindows']} "
            f"malware_positives={summary['malwarePositives']}"
        )

    if not args.skip_thaw:
        result = thaw_rejected_samples()
        print(
            "Sample queue refreshed: "
            f"thawed={result['thawed']} "
            f"ready={result['ready']} "
            f"review={result['review']} "
            f"pending={result['pending']} "
            f"trained={result['trained']} "
            f"total={result['total']}"
        )

    if checkpoint is not None:
        print("If the new setup behaves badly, roll back to the checkpoint above.")


if __name__ == "__main__":
    main()
