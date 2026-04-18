from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

import train_ai
import train_malware
from online_models import (
    ATTACK_ONLINE_MODEL_PATH,
    MALWARE_ONLINE_MODEL_PATH,
    MissingRiverDependency,
    build_attack_model,
    build_malware_model,
    save_online_models,
)

BASE_DIR = Path(__file__).resolve().parent
ATTACK_BOOST_FACTOR = 3


def load_unsw_dataframe() -> pd.DataFrame:
    dfs = []
    for name in train_ai.CSV_FILES:
        csv_path = BASE_DIR / name
        if not csv_path.exists():
            raise FileNotFoundError(f'Missing training CSV: {csv_path}')
        df = pd.read_csv(csv_path, header=None, low_memory=False)
        df.columns = train_ai.UNSW_COLUMNS
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)


def build_attack_bootstrap_dataset(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    feat = train_ai.build_window_features(df.copy())
    ps_ssh_mask = (
        (feat['uniq_dports'] > 20) |
        ((feat['top_is_22'] == 1) & (feat['flows'] > 15))
    )
    ps_ssh_attack = feat[ps_ssh_mask & (feat['attack_label'] == 1)]
    boosted = pd.concat([ps_ssh_attack] * ATTACK_BOOST_FACTOR, ignore_index=True)
    feat_boosted = pd.concat([feat, boosted], ignore_index=True)
    X = feat_boosted.drop(columns=['attack_label'])
    y = feat_boosted['attack_label'].astype(int)
    return X, y


def build_malware_bootstrap_dataset(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    feat = train_malware.build_window_features(df.copy())
    X_base = feat.drop(columns=['malware_label'])

    synth = train_malware.make_synth_rows(
        train_malware.SYN_MINER,
        train_malware.SYN_BACKDOOR,
        train_malware.SYN_RANSOM,
    )
    for col in X_base.columns:
        if col not in synth.columns:
            synth[col] = 0.0
    synth = synth[X_base.columns.tolist() + ['malware_label']]

    feat_plus = pd.concat([feat, synth], ignore_index=True)
    X = feat_plus.drop(columns=['malware_label'])
    y = feat_plus['malware_label'].astype(int)
    X, y = train_malware.oversample_minority(X, y)
    return X, y


def bootstrap_binary_model(model, X: pd.DataFrame, y: pd.Series, epochs: int, seed: int) -> None:
    frame = X.copy()
    frame['_label'] = y.astype(int).values
    for epoch in range(epochs):
        shuffled = frame.sample(frac=1.0, random_state=seed + epoch).reset_index(drop=True)
        for record in shuffled.to_dict(orient='records'):
            label = bool(int(record.pop('_label')))
            features = {k: float(v) for k, v in record.items()}
            model.learn_one(features, label)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Bootstrap River online models from the existing UNSW training data.')
    parser.add_argument('--attack-epochs', type=int, default=2, help='How many online passes to make over the attack bootstrap dataset.')
    parser.add_argument('--malware-epochs', type=int, default=2, help='How many online passes to make over the malware bootstrap dataset.')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        attack_model = build_attack_model()
        malware_model = build_malware_model()
    except MissingRiverDependency as exc:
        raise SystemExit(str(exc)) from exc

    print('Loading UNSW training data...')
    df = load_unsw_dataframe()
    print(f'Loaded rows: {len(df)}')

    print('Building attack bootstrap dataset...')
    attack_X, attack_y = build_attack_bootstrap_dataset(df)
    print(f'Attack windows: {len(attack_X)} | positives: {int(attack_y.sum())}')

    print('Building malware bootstrap dataset...')
    malware_X, malware_y = build_malware_bootstrap_dataset(df)
    print(f'Malware windows: {len(malware_X)} | positives: {int(malware_y.sum())}')

    print(f'Bootstrapping attack online model for {args.attack_epochs} epoch(s)...')
    bootstrap_binary_model(attack_model, attack_X, attack_y, args.attack_epochs, train_ai.RANDOM_STATE)

    print(f'Bootstrapping malware online model for {args.malware_epochs} epoch(s)...')
    bootstrap_binary_model(malware_model, malware_X, malware_y, args.malware_epochs, train_malware.RANDOM_STATE)

    save_online_models({'attack': attack_model, 'malware': malware_model})
    print('Saved online models:')
    print(f'  - {ATTACK_ONLINE_MODEL_PATH}')
    print(f'  - {MALWARE_ONLINE_MODEL_PATH}')


if __name__ == '__main__':
    main()
