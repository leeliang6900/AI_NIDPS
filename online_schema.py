from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class OnlineSample:
    event_id: str
    ts: str
    src: str
    dst: str
    rule: str
    category: str
    features: Dict[str, float] = field(default_factory=dict)
    xgb_attack_score: Optional[float] = None
    xgb_malware_score: Optional[float] = None
    current_attack_score: Optional[float] = None
    current_malware_score: Optional[float] = None
    online_attack_score: Optional[float] = None
    online_malware_score: Optional[float] = None
    decision: str = ''
    attack_label: Optional[int] = None
    malware_label: Optional[int] = None
    family_label: Optional[str] = None
    display_label: Optional[str] = None
    family_confidence: Optional[str] = None
    family_source: Optional[str] = None
    novelty_score: Optional[float] = None
    learn_eligible: bool = False
    learn_weight: float = 0.0
    learn_reason: Optional[str] = None
    learn_signature: Optional[str] = None
    reject_count: int = 0
    train_attempt_count: int = 0
    last_train_attempt_at: Optional[str] = None
    last_rejected_at: Optional[str] = None
    last_reject_reason: Optional[str] = None
    label_status: str = 'pending'
    label_source: Optional[str] = None
    trained: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "OnlineSample":
        return cls(**payload)
