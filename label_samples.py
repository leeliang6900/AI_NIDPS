from __future__ import annotations

import argparse
from typing import Iterable, List

from online_schema import OnlineSample
from online_store import OnlineSampleStore, UNSET


STORE = OnlineSampleStore()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='List and label online-learning samples captured by nidps_monitor.py.'
    )
    parser.add_argument('--list', action='store_true', help='List samples instead of updating a label.')
    parser.add_argument('--status', choices=['pending', 'candidate', 'ready', 'trained', 'all'], default='pending', help='Which sample status to list.')
    parser.add_argument('--limit', type=int, default=20, help='How many samples to show when listing.')
    parser.add_argument('--event-id', help='Event ID to label.')
    parser.add_argument('--attack', type=int, choices=[0, 1], help='Attack label to store (0 or 1).')
    parser.add_argument('--malware', type=int, choices=[0, 1], help='Malware label to store (0 or 1).')
    parser.add_argument('--source', default='manual', help='Label source to record, for example manual or honeypot.')
    return parser.parse_args()


def sample_matches_status(sample: OnlineSample, status: str) -> bool:
    if status == 'all':
        return True
    if status == 'pending':
        return sample.label_status == 'pending'
    if status == 'candidate':
        return sample.label_status == 'candidate'
    if status == 'ready':
        return sample.label_status == 'labeled' and not sample.trained and getattr(sample, 'learn_eligible', False)
    if status == 'trained':
        return sample.trained
    return False


def iter_matching_samples(status: str) -> List[OnlineSample]:
    return [s for s in STORE.iter_samples() if sample_matches_status(s, status)]


def score_text(value) -> str:
    if value is None or value == '':
        return '-'
    try:
        return f'{float(value):.3f}'
    except Exception:
        return str(value)


def print_samples(samples: Iterable[OnlineSample], limit: int) -> None:
    shown = list(samples)[-max(limit, 0):]
    if not shown:
        print('No matching online samples found.')
        return

    for sample in reversed(shown):
        state = 'trained' if sample.trained else sample.label_status
        print(f'[{state}] {sample.ts} | {sample.event_id}')
        print(f'  {sample.rule} ({sample.category}) | {sample.src} -> {sample.dst}')
        print(f'  current atk={score_text(sample.xgb_attack_score)} mal={score_text(sample.xgb_malware_score)} | shadow atk={score_text(sample.online_attack_score)} mal={score_text(sample.online_malware_score)}')
        print(f'  labels attack={sample.attack_label if sample.attack_label is not None else "-"} malware={sample.malware_label if sample.malware_label is not None else "-"} source={sample.label_source or "-"}')
        print()


def label_sample(event_id: str, attack_label, malware_label, source: str) -> None:
    if attack_label is None and malware_label is None:
        raise SystemExit('Provide at least one label with --attack or --malware.')
    next_attack = attack_label if attack_label is not None else UNSET
    next_malware = malware_label if malware_label is not None else UNSET
    updated = STORE.update_labels(event_id, next_attack, next_malware, source)
    if not updated:
        raise SystemExit(f'Event not found: {event_id}')
    print(f'Labeled {event_id} | attack={attack_label if attack_label is not None else "unchanged"} malware={malware_label if malware_label is not None else "unchanged"} source={source}')


def main() -> None:
    args = parse_args()
    if args.event_id:
        label_sample(args.event_id, args.attack, args.malware, args.source)
        return

    status = args.status
    if not args.list and status == 'pending':
        # Default behavior with no args: show pending samples.
        args.list = True

    if args.list:
        print_samples(iter_matching_samples(status), args.limit)
        return

    raise SystemExit('Nothing to do. Use --list or provide --event-id.')


if __name__ == '__main__':
    main()
