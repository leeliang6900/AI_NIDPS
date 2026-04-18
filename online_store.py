from __future__ import annotations

from contextlib import contextmanager
import json
from datetime import datetime
import os
from pathlib import Path
from typing import Iterable, Iterator, Optional

from online_schema import OnlineSample

DEFAULT_ONLINE_SAMPLES_PATH = Path(__file__).resolve().with_name('online_learning') / 'online_samples.jsonl'
UNSET = object()

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class OnlineSampleStore:
    def __init__(self, path: Path | str = DEFAULT_ONLINE_SAMPLES_PATH):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(f"{self.path.suffix}.lock")

    def ensure_exists(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self.lock_path.touch(exist_ok=True)

    @contextmanager
    def _locked(self):
        self.ensure_exists()
        with self.lock_path.open("r+b") as lock_fh:
            if self.lock_path.stat().st_size == 0:
                lock_fh.seek(0)
                lock_fh.write(b"0")
                lock_fh.flush()
            lock_fh.seek(0)
            if os.name == "nt":
                msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                lock_fh.seek(0)
                if os.name == "nt":
                    msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def _read_samples_locked(self) -> list[OnlineSample]:
        if not self.path.exists():
            return []
        samples: list[OnlineSample] = []
        with self.path.open('r', encoding='utf-8-sig') as fh:
            for line in fh:
                line = line.lstrip('\ufeff').strip()
                if not line:
                    continue
                try:
                    samples.append(OnlineSample.from_dict(json.loads(line)))
                except json.JSONDecodeError:
                    continue
        return samples

    def _rewrite_locked(self, samples: Iterable[OnlineSample]) -> None:
        tmp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        with tmp_path.open('w', encoding='utf-8') as fh:
            for sample in samples:
                fh.write(json.dumps(sample.to_dict(), ensure_ascii=False) + '\n')
        os.replace(tmp_path, self.path)

    def list_samples(self) -> list[OnlineSample]:
        with self._locked():
            return self._read_samples_locked()

    def get_samples_by_event_ids(self, event_ids: Iterable[str]) -> dict[str, OnlineSample]:
        wanted = {str(event_id) for event_id in event_ids if str(event_id)}
        if not wanted:
            return {}
        with self._locked():
            return {
                sample.event_id: sample
                for sample in self._read_samples_locked()
                if sample.event_id in wanted
            }

    def append(self, sample: OnlineSample) -> None:
        with self._locked():
            with self.path.open('a', encoding='utf-8') as fh:
                fh.write(json.dumps(sample.to_dict(), ensure_ascii=False) + '\n')

    def iter_samples(self) -> Iterator[OnlineSample]:
        for sample in self.list_samples():
            yield sample

    def list_unlabeled(self) -> list[OnlineSample]:
        return [sample for sample in self.list_samples() if sample.label_status in {'pending', 'candidate'}]

    def list_ready_for_training(self) -> list[OnlineSample]:
        return [
            sample
            for sample in self.list_samples()
            if sample.label_status == 'labeled'
            and not sample.trained
            and bool(getattr(sample, 'learn_eligible', False))
        ]

    def rewrite(self, samples: Iterable[OnlineSample]) -> None:
        with self._locked():
            self._rewrite_locked(samples)

    def rewrite_preserving_new_samples(self, samples: Iterable[OnlineSample]) -> None:
        updated_samples = list(samples)
        def identity_key(sample: OnlineSample) -> tuple[object, object, object, object]:
            return (
                getattr(sample, 'ts', getattr(sample, 'timestamp', None)),
                getattr(sample, 'src', getattr(sample, 'src_ip', None)),
                getattr(sample, 'dst', getattr(sample, 'dst_ip', None)),
                getattr(sample, 'rule', None),
            )
        updated_event_ids = {sample.event_id for sample in updated_samples if getattr(sample, 'event_id', None)}
        updated_identity_keys = {
            identity_key(sample)
            for sample in updated_samples
            if not getattr(sample, 'event_id', None)
        }

        with self._locked():
            current_samples = self._read_samples_locked()
            merged_samples = list(updated_samples)
            for current in current_samples:
                current_event_id = getattr(current, 'event_id', None)
                if current_event_id:
                    if current_event_id in updated_event_ids:
                        continue
                else:
                    current_identity_key = identity_key(current)
                    if current_identity_key in updated_identity_keys:
                        continue
                merged_samples.append(current)
            self._rewrite_locked(merged_samples)

    def _apply_label_update(
        self,
        sample: OnlineSample,
        attack_label: Optional[int] | object,
        malware_label: Optional[int] | object,
        label_source: str,
    ) -> None:
        if attack_label is not UNSET:
            sample.attack_label = attack_label
        if malware_label is not UNSET:
            sample.malware_label = malware_label
        sample.label_source = label_source
        sample.label_status = 'labeled'
        if str(label_source or '').startswith('auto'):
            sample.learn_eligible = False
            sample.learn_reason = 'awaiting_policy_refresh'
        else:
            sample.learn_eligible = True
            sample.learn_reason = 'manual_label'
        sample.learn_signature = None
        sample.reject_count = 0
        sample.train_attempt_count = 0
        sample.last_train_attempt_at = None
        sample.last_rejected_at = None
        sample.last_reject_reason = None
        # Any relabel should require the sample to be learned again.
        sample.trained = False

    def update_labels_batch(
        self,
        event_ids: Iterable[str],
        attack_label: Optional[int] | object,
        malware_label: Optional[int] | object,
        label_source: str,
    ) -> int:
        wanted = {str(event_id).strip() for event_id in event_ids if str(event_id).strip()}
        if not wanted:
            return 0
        with self._locked():
            samples = self._read_samples_locked()
            updated = 0
            for sample in samples:
                if sample.event_id not in wanted:
                    continue
                self._apply_label_update(sample, attack_label, malware_label, label_source)
                updated += 1
            if updated:
                self._rewrite_locked(samples)
            return updated

    def update_labels(
        self,
        event_id: str,
        attack_label: Optional[int] | object,
        malware_label: Optional[int] | object,
        label_source: str,
    ) -> bool:
        return bool(
            self.update_labels_batch(
                [event_id],
                attack_label=attack_label,
                malware_label=malware_label,
                label_source=label_source,
            )
        )

    def mark_trained(self, event_id: str) -> bool:
        with self._locked():
            samples = self._read_samples_locked()
            updated = False
            for sample in samples:
                if sample.event_id != event_id:
                    continue
                sample.trained = True
                updated = True
                break
            if updated:
                self._rewrite_locked(samples)
            return updated

    def mark_trained_batch(self, event_ids: Iterable[str]) -> int:
        event_ids = {str(event_id) for event_id in event_ids if str(event_id)}
        if not event_ids:
            return 0
        with self._locked():
            samples = self._read_samples_locked()
            updated = 0
            for sample in samples:
                if sample.event_id not in event_ids:
                    continue
                if sample.trained:
                    continue
                sample.trained = True
                updated += 1
            if updated:
                self._rewrite_locked(samples)
            return updated

    def mark_training_attempt_batch(self, event_ids: Iterable[str]) -> int:
        event_ids = {str(event_id) for event_id in event_ids if str(event_id)}
        if not event_ids:
            return 0
        with self._locked():
            samples = self._read_samples_locked()
            updated = 0
            attempted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for sample in samples:
                if sample.event_id not in event_ids or sample.trained:
                    continue
                sample.train_attempt_count = int(getattr(sample, 'train_attempt_count', 0) or 0) + 1
                sample.last_train_attempt_at = attempted_at
                updated += 1
            if updated:
                self._rewrite_locked(samples)
            return updated

    def mark_rejected_batch(self, event_ids: Iterable[str], reason: str, max_retries: int = 2) -> int:
        event_ids = {str(event_id) for event_id in event_ids if str(event_id)}
        if not event_ids:
            return 0
        with self._locked():
            samples = self._read_samples_locked()
            updated = 0
            rejected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for sample in samples:
                if sample.event_id not in event_ids or sample.trained:
                    continue
                sample.reject_count = int(getattr(sample, 'reject_count', 0) or 0) + 1
                sample.last_rejected_at = rejected_at
                sample.last_reject_reason = str(reason or '')
                if int(sample.reject_count or 0) >= max(int(max_retries or 0), 1):
                    sample.learn_eligible = False
                    sample.learn_reason = 'retry_limit_reached'
                else:
                    sample.learn_eligible = True
                    sample.learn_reason = 'retry_after_failed_train'
                updated += 1
            if updated:
                self._rewrite_locked(samples)
            return updated

    def mark_untrainable_batch(self, event_ids: Iterable[str], reason: str = 'missing_trainable_features') -> int:
        event_ids = {str(event_id) for event_id in event_ids if str(event_id)}
        if not event_ids:
            return 0
        with self._locked():
            samples = self._read_samples_locked()
            updated = 0
            marked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for sample in samples:
                if sample.event_id not in event_ids or sample.trained:
                    continue
                sample.learn_eligible = False
                sample.learn_weight = 0.0
                sample.learn_reason = str(reason or 'missing_trainable_features')
                sample.last_rejected_at = marked_at
                sample.last_reject_reason = str(reason or 'missing_trainable_features')
                sample.reject_count = max(int(getattr(sample, 'reject_count', 0) or 0), 1)
                updated += 1
            if updated:
                self._rewrite_locked(samples)
            return updated
