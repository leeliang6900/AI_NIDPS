from __future__ import annotations

import math
from typing import Iterable

from online_models import MissingRiverDependency, load_online_models, predict_online_scores


STABLE_KNOWN_FAMILIES = {
    'attack.port_scan',
    'attack.icmp_flood',
    'attack.tcp_flood',
    'attack.udp_flood',
    'attack.http_flood',
    'attack.conn_flood',
    'attack.bruteforce.ssh',
    'attack.bruteforce.ftp',
    'attack.bruteforce.telnet',
    'attack.bruteforce.rdp',
    'attack.bruteforce.winbox',
    'attack.high_port_suspicious',
    'malware.crypto_miner',
    'malware.c2_backdoor',
    'malware.ransomware_precheck',
    'malware.dns_tunnel',
    'malware.data_exfil',
    'malware.c2_beacon',
    'benign.observed.ping',
    'benign.observed.ssh',
    'benign.victim_leg',
    'benign.infrastructure.dhcp',
    'benign.infrastructure.dns',
    'benign.infrastructure.ntp',
}

TRUSTED_AUTO_LABEL_SOURCES = {
    'auto_family_infrastructure_safe',
    'auto_local_observed_safe',
    'auto_local_victim_leg_safe',
    'auto_family_broadcast_safe',
}

TRUSTED_AUTO_FAMILIES = {
    'benign.observed.ping',
    'benign.observed.ssh',
    'benign.victim_leg',
    'benign.infrastructure.dhcp',
    'benign.infrastructure.dns',
    'benign.infrastructure.ntp',
    'benign.broadcast_discovery_like',
}

BENIGN_INFRASTRUCTURE_FAMILIES = {
    'benign.infrastructure.dhcp',
    'benign.infrastructure.dns',
    'benign.infrastructure.ntp',
}

REVIEW_LOW_CONFIDENCE = {'low'}
REVIEW_NOVELTY_FLOOR = 0.65
REVIEW_MEDIUM_SCORE_FLOOR = 0.60
REVIEW_HIGH_SCORE_FLOOR = 0.85
REVIEW_UNCERTAIN_SOURCE_PREFIXES = (
    'auto_family_default_',
    'auto_family_unknown_',
)
REVIEW_ATTACK_RULE_TOKENS = (
    'FLOOD',
    'SCAN',
    'BRUTE_FORCE',
    'SUSP_HIGH_PORT',
)
REVIEW_MALWARE_RULE_TOKENS = (
    'CRYPTO_MINER',
    'C2_BACKDOOR',
    'DNS_TUNNEL',
    'DATA_EXFIL',
    'C2_BEACON',
    'RANSOMWARE_PRECHECK',
)
REVIEW_SUSPICIOUS_FEATURE_FLAGS = (
    'top_is_3333',
    'top_is_4444',
    'top_is_5555',
    'top_is_9001',
    'top_is_1337',
    'top_is_14444',
    'top_is_miner',
    'top_is_backdoor',
)

BENIGN_SCORE_CEILING = 0.18
STABLE_SCORE_GAP_TRIGGER = 0.25
POSITIVE_RECALIBRATION_TARGET = 0.90
POSITIVE_GAP_MARGIN = 0.04
HIGH_NOVELTY_RECALIBRATION_FLOOR = 0.98
STABLE_FAMILY_SEED_WEIGHT = 7.0
MAX_REJECT_RETRIES = 3
SHADOW_POSITIVE_TARGET = 0.88
SHADOW_GAP_TRIGGER = 0.12
SHADOW_HIGH_NOVELTY_FLOOR = 0.95
DISPLAY_THR_ATTACK = {
    'ICMP_FLOOD': 0.55,
    'HTTP_FLOOD': 0.72,
    'TCP_FLOOD': 0.72,
    'UDP_FLOOD': 0.72,
    'CONN_FLOOD': 0.74,
    'PORT_SCAN': 0.60,
    'SSH_BRUTE_FORCE': 0.50,
    'FTP_BRUTE_FORCE': 0.50,
    'TELNET_BRUTE_FORCE': 0.50,
    'RDP_BRUTE_FORCE': 0.50,
    'WINBOX_BRUTE_FORCE': 0.50,
    'DNS_TUNNEL': 0.70,
    'DATA_EXFIL': 0.72,
    'SUSP_HIGH_PORT': 0.70,
    'C2_BEACON': 0.75,
    'CRYPTO_MINER': 0.70,
    'C2_BACKDOOR': 0.70,
    'RANSOMWARE_PRECHECK': 0.70,
}
DISPLAY_THR_MAL = {
    'C2_BEACON': 0.60,
    'DNS_TUNNEL': 0.65,
    'DATA_EXFIL': 0.65,
    'CRYPTO_MINER': 0.60,
    'C2_BACKDOOR': 0.60,
    'RANSOMWARE_PRECHECK': 0.60,
}
DISPLAY_THR_ATTACK_DEFAULT = 0.70
DISPLAY_THR_MAL_DEFAULT = 0.65
DISPLAY_RANSOMWARE_PRECHECK_RAW_PASS_MAL = 0.230

def _num(value) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def is_manual_label_source(value) -> bool:
    source = str(value or '').strip()
    return bool(source) and not source.startswith('auto')


def is_trusted_auto_label(label_source, family_source, family_label) -> bool:
    source = str(label_source or '').strip()
    family_source = str(family_source or '').strip()
    family_label = str(family_label or '').strip().lower()
    if is_manual_label_source(source):
        return True
    if not source.startswith('auto'):
        return False
    if family_source == 'known_rule':
        return True
    if source in TRUSTED_AUTO_LABEL_SOURCES:
        return True
    if family_label in TRUSTED_AUTO_FAMILIES:
        return True
    return False


def is_benign_infrastructure_family(family_label) -> bool:
    return str(family_label or '').strip().lower() in BENIGN_INFRASTRUCTURE_FAMILIES


def should_hold_for_review_fields(label_source, family_source, family_label) -> bool:
    source = str(label_source or '').strip()
    if not source.startswith('auto'):
        return False
    if is_trusted_auto_label(source, family_source, family_label):
        return False
    return source.startswith(REVIEW_UNCERTAIN_SOURCE_PREFIXES)


def _review_score(sample, current_attr: str, xgb_attr: str, online_attr: str) -> float:
    current_value = getattr(sample, current_attr, None)
    xgb_value = getattr(sample, xgb_attr, None)
    online_value = getattr(sample, online_attr, None)
    return _primary_score(
        current_value if current_value not in (None, '') else xgb_value,
        online_value,
    )


def _review_feature_flag(sample, name: str) -> bool:
    features = getattr(sample, 'features', None) or {}
    return _num(features.get(name)) >= 1.0


def _review_low_confidence(sample) -> bool:
    return str(getattr(sample, 'family_confidence', '') or '').strip().lower() in REVIEW_LOW_CONFIDENCE


def _review_unknown_or_uncertain_family(sample) -> bool:
    family_label = str(getattr(sample, 'family_label', '') or '').strip().lower()
    label_source = str(getattr(sample, 'label_source', '') or '').strip().lower()
    family_source = str(getattr(sample, 'family_source', '') or '').strip().lower()
    rule = str(getattr(sample, 'rule', '') or '').strip().upper()

    if label_source.startswith(REVIEW_UNCERTAIN_SOURCE_PREFIXES):
        return True
    if family_source in {'behavior_heuristic', 'unknown', 'unknown_family'}:
        if 'unknown' in family_label or 'unclassified' in family_label:
            return True
        if family_label.endswith('_like'):
            return True
    if family_label.startswith('unknown.') or '.unknown_' in family_label or 'unclassified' in family_label:
        return True
    if rule == 'OBS_UNKNOWN':
        return True
    return False


def _review_high_novelty(sample) -> bool:
    novelty = _num(getattr(sample, 'novelty_score', 0.0))
    return novelty >= REVIEW_NOVELTY_FLOOR


def _review_risk_bucket(sample) -> str:
    decision = str(getattr(sample, 'decision', '') or '').upper()
    category = str(getattr(sample, 'category', '') or '').upper()
    rule = str(getattr(sample, 'rule', '') or '').upper()
    family_label = str(getattr(sample, 'family_label', '') or '').lower()
    features = getattr(sample, 'features', None) or {}
    flows = _num(features.get('flows'))
    uniq_dports = _num(features.get('uniq_dports'))
    bytes_rate = _num(features.get('bytes_rate'))

    attack_score = _review_score(sample, 'current_attack_score', 'xgb_attack_score', 'online_attack_score')
    malware_score = _review_score(sample, 'current_malware_score', 'xgb_malware_score', 'online_malware_score')
    max_score = max(attack_score, malware_score)

    suspicious_rule = any(token in rule for token in REVIEW_ATTACK_RULE_TOKENS + REVIEW_MALWARE_RULE_TOKENS)
    suspicious_family = family_label.startswith('attack.') or family_label.startswith('malware.')
    suspicious_feature = any(_review_feature_flag(sample, name) for name in REVIEW_SUSPICIOUS_FEATURE_FLAGS)

    if decision.startswith('BLOCKED') or 'HONEYPOT' in decision:
        return 'high'
    if max_score >= REVIEW_HIGH_SCORE_FLOOR:
        return 'high'
    if category in {'ATTACK', 'MALWARE'} and max_score >= 0.50:
        return 'high'

    if max_score >= REVIEW_MEDIUM_SCORE_FLOOR:
        return 'medium'
    if suspicious_rule and (flows >= 3 or uniq_dports >= 3 or bytes_rate >= 250 or suspicious_feature):
        return 'medium'
    if suspicious_family and (suspicious_feature or flows >= 3 or uniq_dports >= 3):
        return 'medium'
    if category in {'ATTACK', 'MALWARE'} and (suspicious_rule or suspicious_feature or flows >= 5):
        return 'medium'

    return 'low'


def _review_inconsistent(sample) -> bool:
    decision = str(getattr(sample, 'decision', '') or '').upper()
    rule = str(getattr(sample, 'rule', '') or '').upper()
    family_label = str(getattr(sample, 'family_label', '') or '').strip().lower()
    attack_label = getattr(sample, 'attack_label', None)
    malware_label = getattr(sample, 'malware_label', None)
    attack_score = _review_score(sample, 'current_attack_score', 'xgb_attack_score', 'online_attack_score')
    malware_score = _review_score(sample, 'current_malware_score', 'xgb_malware_score', 'online_malware_score')
    suspicious_rule = any(token in rule for token in REVIEW_ATTACK_RULE_TOKENS + REVIEW_MALWARE_RULE_TOKENS)

    if family_label.startswith('benign.'):
        if attack_label == 1 or malware_label == 1:
            return True
        if max(attack_score, malware_score) >= REVIEW_MEDIUM_SCORE_FLOOR:
            return True
        if decision.startswith('BLOCKED') or suspicious_rule:
            return True

    if family_label.startswith('attack.'):
        if attack_label != 1:
            return True
        if malware_label == 1 and malware_score >= max(attack_score + 0.15, REVIEW_MEDIUM_SCORE_FLOOR):
            return True

    if family_label.startswith('malware.'):
        if malware_label != 1:
            return True
        if attack_label == 1 and attack_score >= max(malware_score + 0.15, REVIEW_MEDIUM_SCORE_FLOOR):
            return True

    return False


def should_hold_for_review(sample) -> bool:
    if getattr(sample, 'attack_label', None) is None and getattr(sample, 'malware_label', None) is None:
        return False
    label_source = getattr(sample, 'label_source', None)
    family_source = getattr(sample, 'family_source', None)
    family_label = getattr(sample, 'family_label', None)

    if not str(label_source or '').strip().startswith('auto'):
        return False
    if is_trusted_auto_label(label_source, family_source, family_label):
        return False

    low_confidence = _review_low_confidence(sample)
    uncertain_family = _review_unknown_or_uncertain_family(sample)
    high_novelty = _review_high_novelty(sample)
    risk_bucket = _review_risk_bucket(sample)
    inconsistent = _review_inconsistent(sample)

    if inconsistent:
        return True
    if low_confidence and risk_bucket in {'medium', 'high'}:
        return True
    if uncertain_family and risk_bucket in {'medium', 'high'}:
        return True
    if high_novelty and risk_bucket in {'medium', 'high'}:
        return True
    return False


def _family_identity(sample) -> str:
    return str(sample.family_label or sample.rule or sample.category or 'unknown').strip().lower()


def _primary_score(preferred, fallback) -> float:
    if preferred not in (None, ''):
        return _num(preferred)
    return _num(fallback)


def _calibrated_exp_score(raw_score: float, threshold: float, raw_pass_score: float) -> float:
    raw = min(max(float(raw_score), 0.0), 1.0)
    thr = min(max(float(threshold), 1e-6), 0.999999)
    pass_raw = max(float(raw_pass_score), 1e-6)
    scale = -math.log(1.0 - thr) / pass_raw
    return 1.0 - math.exp(-scale * raw)


def _shadow_display_scores(sample) -> tuple[float, float]:
    rule = str(sample.rule or '').upper()
    category = str(sample.category or '').upper()
    attack_raw = _num(getattr(sample, 'online_attack_score', 0.0))
    malware_raw = _num(getattr(sample, 'online_malware_score', 0.0))

    attack_thr = DISPLAY_THR_ATTACK.get(rule, DISPLAY_THR_ATTACK_DEFAULT)
    malware_thr = DISPLAY_THR_MAL.get(rule, DISPLAY_THR_MAL_DEFAULT)
    attack_display = _calibrated_exp_score(attack_raw, attack_thr, attack_thr) if category in {'ATTACK', 'MALWARE'} else 0.0
    malware_display = 0.0
    if category == 'MALWARE':
        raw_pass = DISPLAY_RANSOMWARE_PRECHECK_RAW_PASS_MAL if rule == 'RANSOMWARE_PRECHECK' else malware_thr
        malware_display = _calibrated_exp_score(malware_raw, malware_thr, raw_pass)
    return round(attack_display, 4), round(malware_display, 4)


def _refresh_shadow_scores(samples: list) -> bool:
    candidates = []
    for sample in samples:
        if sample.attack_label is None and sample.malware_label is None:
            continue
        features = getattr(sample, 'features', None) or {}
        cleaned = {}
        for key, value in features.items():
            try:
                cleaned[str(key)] = float(value)
            except Exception:
                continue
        if cleaned:
            candidates.append((sample, cleaned))
    if not candidates:
        return False

    try:
        models = load_online_models()
    except MissingRiverDependency:
        return False
    except Exception:
        return False

    changed = False
    for sample, features in candidates:
        try:
            attack_score, malware_score = predict_online_scores(models, features)
        except Exception:
            continue
        attack_score = round(float(attack_score), 6)
        malware_score = round(float(malware_score), 6)
        if _num(getattr(sample, 'online_attack_score', None)) != attack_score:
            sample.online_attack_score = attack_score
            changed = True
        if _num(getattr(sample, 'online_malware_score', None)) != malware_score:
            sample.online_malware_score = malware_score
            changed = True
    return changed


def _bucket(value: float, cutoffs: tuple[float, ...]) -> str:
    for cutoff in cutoffs:
        if value <= cutoff:
            return str(int(cutoff))
    return f'{int(cutoffs[-1])}+'


def _cutoff_label(cutoff: float) -> str:
    cutoff = float(cutoff)
    if cutoff.is_integer():
        return str(int(cutoff))
    return str(cutoff).rstrip('0').rstrip('.')


def _bucket_label(value: float, cutoffs: tuple[float, ...]) -> str:
    for cutoff in cutoffs:
        if value <= cutoff:
            return _cutoff_label(cutoff)
    return f'{_cutoff_label(cutoffs[-1])}+'


def build_learning_signature(sample) -> str:
    feat = sample.features or {}
    family = str(sample.family_label or sample.rule or sample.category or 'unknown').strip() or 'unknown'
    proto = int(_num(feat.get('proto_mode')))
    flows = _bucket(_num(feat.get('flows')), (2, 10, 50, 250, 1000))
    uniq_dports = _bucket(_num(feat.get('uniq_dports')), (1, 3, 10, 50))
    pkts_rate = _bucket(_num(feat.get('pkts_rate')), (5, 20, 100, 1000, 5000))
    bytes_rate = _bucket(_num(feat.get('bytes_rate')), (100, 1000, 10000, 100000, 1000000))
    atk = 1 if sample.attack_label == 1 else 0
    mal = 1 if sample.malware_label == 1 else 0
    return '|'.join([
        family,
        f'proto:{proto}',
        f'flows:{flows}',
        f'dports:{uniq_dports}',
        f'pkts:{pkts_rate}',
        f'bytes:{bytes_rate}',
        f'a:{atk}',
        f'm:{mal}',
    ])


def build_family_variant_signature(sample) -> str:
    feat = sample.features or {}
    family = str(sample.family_label or sample.rule or sample.category or 'unknown').strip() or 'unknown'
    proto = int(_num(feat.get('proto_mode')))
    flows = _bucket_label(_num(feat.get('flows')), (2, 5, 10, 20, 50, 100, 250, 1000, 5000))
    uniq_dports = _bucket_label(_num(feat.get('uniq_dports')), (1, 2, 3, 5, 10, 20, 50, 100))
    pkts_rate = _bucket_label(_num(feat.get('pkts_rate')), (1, 5, 20, 50, 100, 250, 1000, 5000))
    bytes_rate = _bucket_label(_num(feat.get('bytes_rate')), (100, 500, 1000, 5000, 10000, 50000, 100000, 1000000))
    top_port_ratio = _bucket_label(_num(feat.get('top_port_ratio')), (0.25, 0.50, 0.80, 0.95, 1.0))
    dport_entropy = _bucket_label(_num(feat.get('dport_entropy')), (0.2, 1.0, 2.0, 4.0, 8.0, 16.0))
    flow_ratio = _bucket_label(_num(feat.get('flow_ratio')), (0.5, 1.0, 2.0, 10.0, 100.0, 1000.0))
    atk = _bucket_label(_num(getattr(sample, 'xgb_attack_score', 0.0)), (0.25, 0.50, 0.70, 0.85, 0.95, 1.0))
    mal = _bucket_label(_num(getattr(sample, 'xgb_malware_score', 0.0)), (0.25, 0.50, 0.70, 0.85, 0.95, 1.0))
    return '|'.join([
        family,
        f'proto:{proto}',
        f'flows:{flows}',
        f'dports:{uniq_dports}',
        f'pkts:{pkts_rate}',
        f'bytes:{bytes_rate}',
        f'top:{top_port_ratio}',
        f'ent:{dport_entropy}',
        f'ratio:{flow_ratio}',
        f'xgbA:{atk}',
        f'xgbM:{mal}',
    ])


def is_novel_family(sample) -> bool:
    family_label = str(sample.family_label or '')
    family_source = str(sample.family_source or '')
    novelty = _num(sample.novelty_score)
    if family_source == 'behavior_heuristic':
        return True
    if novelty >= 0.35:
        return True
    if family_label.startswith('unknown.'):
        return True
    if '.unknown_' in family_label:
        return True
    if family_label.endswith('_like'):
        return True
    return False


def needs_stable_family_refresh(sample) -> bool:
    family_label = str(sample.family_label or '')
    novelty = _num(sample.novelty_score)
    current_attack = _primary_score(getattr(sample, 'current_attack_score', None), getattr(sample, 'xgb_attack_score', 0.0))
    current_malware = _primary_score(getattr(sample, 'current_malware_score', None), getattr(sample, 'xgb_malware_score', 0.0))
    shadow_attack, shadow_malware = _shadow_display_scores(sample)

    if family_label.startswith('attack.') and sample.attack_label == 1:
        if shadow_attack < SHADOW_POSITIVE_TARGET:
            return True
        if (current_attack - shadow_attack) >= SHADOW_GAP_TRIGGER:
            return True
        if current_attack < POSITIVE_RECALIBRATION_TARGET:
            return True
        if novelty >= 0.25 and shadow_attack < SHADOW_HIGH_NOVELTY_FLOOR:
            return True

    if family_label.startswith('malware.') and sample.malware_label == 1:
        if shadow_malware < SHADOW_POSITIVE_TARGET:
            return True
        if (current_malware - shadow_malware) >= SHADOW_GAP_TRIGGER:
            return True
        if current_malware < POSITIVE_RECALIBRATION_TARGET:
            return True
        if novelty >= 0.25 and shadow_malware < SHADOW_HIGH_NOVELTY_FLOOR:
            return True

    if family_label.startswith('benign.'):
        if sample.attack_label == 0 and max(current_attack, shadow_attack) > BENIGN_SCORE_CEILING:
            return True
        if sample.malware_label == 0 and max(current_malware, shadow_malware) > BENIGN_SCORE_CEILING:
            return True
        if max(shadow_attack - current_attack, shadow_malware - current_malware) >= SHADOW_GAP_TRIGGER:
            return True
        if novelty >= 0.25:
            return True

    return False


def stable_refresh_priority(sample) -> float:
    family_label = str(sample.family_label or '')
    current_attack = _primary_score(getattr(sample, 'current_attack_score', None), getattr(sample, 'xgb_attack_score', 0.0))
    current_malware = _primary_score(getattr(sample, 'current_malware_score', None), getattr(sample, 'xgb_malware_score', 0.0))
    shadow_attack, shadow_malware = _shadow_display_scores(sample)

    if family_label.startswith('attack.') and sample.attack_label == 1:
        shadow_deficit = max(SHADOW_POSITIVE_TARGET - shadow_attack, 0.0)
        current_deficit = max(POSITIVE_RECALIBRATION_TARGET - current_attack, 0.0)
        gap = max(current_attack - shadow_attack, 0.0)
        return round((shadow_deficit * 2.0) + current_deficit + gap, 4)

    if family_label.startswith('malware.') and sample.malware_label == 1:
        shadow_deficit = max(SHADOW_POSITIVE_TARGET - shadow_malware, 0.0)
        current_deficit = max(POSITIVE_RECALIBRATION_TARGET - current_malware, 0.0)
        gap = max(current_malware - shadow_malware, 0.0)
        return round((shadow_deficit * 2.0) + current_deficit + gap, 4)

    if family_label.startswith('benign.'):
        benign_pressure = max(
            max(current_attack - BENIGN_SCORE_CEILING, 0.0),
            max(current_malware - BENIGN_SCORE_CEILING, 0.0),
            max(shadow_attack - BENIGN_SCORE_CEILING, 0.0),
            max(shadow_malware - BENIGN_SCORE_CEILING, 0.0),
        )
        return round(benign_pressure, 4)

    return 0.0


def shadow_learning_pressure(sample) -> float:
    family_label = str(sample.family_label or '')
    current_attack = _primary_score(getattr(sample, 'current_attack_score', None), getattr(sample, 'xgb_attack_score', 0.0))
    current_malware = _primary_score(getattr(sample, 'current_malware_score', None), getattr(sample, 'xgb_malware_score', 0.0))
    shadow_attack, shadow_malware = _shadow_display_scores(sample)

    if family_label.startswith('attack.') and sample.attack_label == 1:
        shadow_deficit = max(SHADOW_POSITIVE_TARGET - shadow_attack, 0.0)
        gap = max(current_attack - shadow_attack, 0.0)
        return round((shadow_deficit * 3.0) + (gap * 1.5), 4)

    if family_label.startswith('malware.') and sample.malware_label == 1:
        shadow_deficit = max(SHADOW_POSITIVE_TARGET - shadow_malware, 0.0)
        gap = max(current_malware - shadow_malware, 0.0)
        return round((shadow_deficit * 3.0) + (gap * 1.5), 4)

    if family_label.startswith('benign.'):
        benign_pressure = max(
            max(shadow_attack - BENIGN_SCORE_CEILING, 0.0),
            max(shadow_malware - BENIGN_SCORE_CEILING, 0.0),
            max(current_attack - shadow_attack, 0.0),
            max(current_malware - shadow_malware, 0.0),
        )
        return round(benign_pressure, 4)

    return 0.0


def should_seed_stable_family(sample) -> bool:
    family_label = str(sample.family_label or '')
    novelty = _num(sample.novelty_score)
    current_attack = _primary_score(getattr(sample, 'current_attack_score', None), getattr(sample, 'xgb_attack_score', 0.0))
    current_malware = _primary_score(getattr(sample, 'current_malware_score', None), getattr(sample, 'xgb_malware_score', 0.0))
    shadow_attack, shadow_malware = _shadow_display_scores(sample)

    if family_label.startswith('attack.') and sample.attack_label == 1:
        return shadow_attack < 0.95 or current_attack < 0.98 or (current_attack - shadow_attack) >= 0.08 or novelty >= 0.20

    if family_label.startswith('malware.') and sample.malware_label == 1:
        return shadow_malware < 0.95 or current_malware < 0.98 or (current_malware - shadow_malware) >= 0.08 or novelty >= 0.20

    if family_label.startswith('benign.'):
        return max(current_attack, current_malware, shadow_attack, shadow_malware) > BENIGN_SCORE_CEILING or novelty >= 0.20

    return novelty >= 0.20


def compute_learning_weight(sample, reason: str, eligible: bool) -> float:
    if not eligible:
        return 0.0

    feat = sample.features or {}
    flows = _num(feat.get('flows'))
    uniq_dports = _num(feat.get('uniq_dports'))
    pkts_rate = _num(feat.get('pkts_rate'))
    bytes_rate = _num(feat.get('bytes_rate'))
    novelty = _num(sample.novelty_score)

    base = {
        'manual_label': 10.0,
        'novel_pattern': 8.0,
        'novel_variant_followup': 7.2,
        'stable_family_seed': STABLE_FAMILY_SEED_WEIGHT,
        'stable_family_recalibration': 6.5,
        'stable_family_followup': 5.8,
        'stable_known_family': 5.2,
        'candidate_pattern': 5.6,
        'candidate_followup': 4.8,
        'retry_after_failed_train': 4.6,
        'retry_limit_reached': 0.0,
    }.get(reason, 4.0)

    size_bonus = 0.0
    if flows >= 20:
        size_bonus += 0.8
    if flows >= 100:
        size_bonus += 0.8
    if uniq_dports >= 5:
        size_bonus += 0.6
    if uniq_dports >= 20:
        size_bonus += 0.6
    if pkts_rate >= 20:
        size_bonus += 0.5
    if pkts_rate >= 100:
        size_bonus += 0.7
    if bytes_rate >= 1000:
        size_bonus += 0.5
    if bytes_rate >= 10000:
        size_bonus += 0.8

    novelty_bonus = 0.0
    if novelty >= 0.35:
        novelty_bonus += 0.8
    if novelty >= 0.60:
        novelty_bonus += 1.0
    if novelty >= 0.80:
        novelty_bonus += 1.0

    shadow_bonus = 0.0
    if reason in {
        'stable_family_seed',
        'stable_family_recalibration',
        'stable_family_followup',
        'stable_known_family',
        'retry_after_failed_train',
    }:
        shadow_bonus = min(shadow_learning_pressure(sample), 3.0)

    weight = base + size_bonus + novelty_bonus + shadow_bonus
    return round(min(weight, 15.0), 2)


def apply_learning_policy(samples: Iterable) -> bool:
    samples = list(samples)
    changed = False
    if _refresh_shadow_scores(samples):
        changed = True
    trained_signature_counts: dict[str, int] = {}
    trained_variant_counts: dict[str, int] = {}
    trained_family_counts: dict[str, int] = {}
    queued_signatures: set[str] = set()
    queued_variant_signatures: set[str] = set()
    queued_benign_infrastructure_families: set[str] = set()
    best_refresh_index_by_variant: dict[str, int] = {}
    best_refresh_priority_by_variant: dict[str, float] = {}

    for idx, sample in enumerate(samples):
        if sample.attack_label is None and sample.malware_label is None:
            continue
        signature = build_learning_signature(sample)
        variant_signature = build_family_variant_signature(sample)
        if sample.trained:
            trained_signature_counts[signature] = trained_signature_counts.get(signature, 0) + 1
            trained_variant_counts[variant_signature] = trained_variant_counts.get(variant_signature, 0) + 1
            family_identity = _family_identity(sample)
            trained_family_counts[family_identity] = trained_family_counts.get(family_identity, 0) + 1
            continue
        if needs_stable_family_refresh(sample):
            priority = stable_refresh_priority(sample)
            previous_priority = best_refresh_priority_by_variant.get(variant_signature, -1.0)
            if priority >= previous_priority:
                best_refresh_priority_by_variant[variant_signature] = priority
                best_refresh_index_by_variant[variant_signature] = idx

    for idx, sample in enumerate(samples):
        label_status = str(getattr(sample, 'label_status', 'pending') or 'pending').lower()
        has_labels = sample.attack_label is not None or sample.malware_label is not None
        review_only = has_labels and should_hold_for_review(sample)
        if review_only and label_status != 'candidate':
            sample.label_status = 'candidate'
            label_status = 'candidate'
            changed = True
        elif has_labels and not review_only and label_status == 'candidate':
            sample.label_status = 'labeled'
            label_status = 'labeled'
            changed = True
        elif not has_labels and label_status == 'candidate':
            sample.label_status = 'pending'
            label_status = 'pending'
            changed = True

        if sample.attack_label is None and sample.malware_label is None:
            next_signature = None
            next_variant_signature = None
            next_eligible = False
            next_reason = 'awaiting_auto_label' if label_status == 'pending' else 'unlabeled'
        elif label_status == 'candidate':
            next_signature = build_learning_signature(sample)
            next_variant_signature = build_family_variant_signature(sample)
            next_eligible = False
            next_reason = 'review_candidate'
        else:
            next_signature = build_learning_signature(sample)
            next_variant_signature = build_family_variant_signature(sample)
            label_source = str(sample.label_source or '')
            family_label = str(sample.family_label or '')
            normalized_family_label = family_label.strip().lower()
            manual_label = is_manual_label_source(label_source)
            reject_count = int(getattr(sample, 'reject_count', 0) or 0)
            train_attempt_count = int(getattr(sample, 'train_attempt_count', 0) or 0)
            family_trained_count = trained_family_counts.get(_family_identity(sample), 0)
            benign_infrastructure_family = is_benign_infrastructure_family(normalized_family_label)
            known_rule_family = family_label in STABLE_KNOWN_FAMILIES or str(sample.family_source or '') == 'known_rule'
            heuristic_family = str(sample.family_source or '').strip().lower() in {
                'behavior_heuristic',
                'unknown',
                'unknown_family',
            }

            if reject_count > train_attempt_count:
                sample.train_attempt_count = reject_count
                train_attempt_count = reject_count
                changed = True
            if reject_count > 0 and not getattr(sample, 'last_train_attempt_at', None) and getattr(sample, 'last_rejected_at', None):
                sample.last_train_attempt_at = getattr(sample, 'last_rejected_at', None)
                changed = True

            if sample.trained:
                next_eligible = False
                next_reason = 'already_trained'
            elif benign_infrastructure_family and reject_count > 0 and train_attempt_count > 0:
                next_eligible = False
                next_reason = 'waiting_after_reject'
            elif known_rule_family and reject_count > 0 and train_attempt_count > 0:
                next_eligible = False
                next_reason = 'waiting_after_reject'
            elif heuristic_family and reject_count > 0 and train_attempt_count > 0:
                next_eligible = False
                next_reason = 'waiting_after_reject'
            elif manual_label and reject_count > 1 and train_attempt_count > 0:
                next_eligible = False
                next_reason = 'waiting_after_reject'
            elif manual_label:
                next_eligible = True
                next_reason = 'manual_label'
                queued_signatures.add(next_signature)
                if benign_infrastructure_family:
                    queued_benign_infrastructure_families.add(normalized_family_label)
            elif reject_count >= MAX_REJECT_RETRIES and train_attempt_count > 0:
                next_eligible = False
                next_reason = 'retry_limit_reached'
            elif (
                benign_infrastructure_family
                and not needs_stable_family_refresh(sample)
                and (
                    family_trained_count > 0
                    or normalized_family_label in queued_benign_infrastructure_families
                )
            ):
                next_eligible = False
                next_reason = 'benign_infrastructure_representative_only'
            elif is_novel_family(sample):
                next_eligible = True
                if trained_signature_counts.get(next_signature, 0) > 0 or next_signature in queued_signatures:
                    next_reason = 'novel_variant_followup'
                else:
                    next_reason = 'novel_pattern'
                    queued_signatures.add(next_signature)
                if benign_infrastructure_family:
                    queued_benign_infrastructure_families.add(normalized_family_label)
            elif known_rule_family:
                next_eligible = True
                if needs_stable_family_refresh(sample):
                    if (
                        best_refresh_index_by_variant.get(next_variant_signature) == idx
                        and next_variant_signature not in queued_variant_signatures
                    ):
                        next_reason = 'stable_family_recalibration'
                        queued_variant_signatures.add(next_variant_signature)
                    else:
                        next_reason = 'stable_family_followup'
                elif should_seed_stable_family(sample) and trained_signature_counts.get(next_signature, 0) <= 0 and next_signature not in queued_signatures:
                    next_reason = 'stable_family_seed'
                    queued_signatures.add(next_signature)
                else:
                    next_reason = 'stable_known_family'
                if benign_infrastructure_family:
                    queued_benign_infrastructure_families.add(normalized_family_label)
            elif trained_signature_counts.get(next_signature, 0) > 0 or next_signature in queued_signatures:
                next_eligible = True
                next_reason = 'candidate_followup'
                if benign_infrastructure_family:
                    queued_benign_infrastructure_families.add(normalized_family_label)
            else:
                next_eligible = True
                next_reason = 'candidate_pattern'
                queued_signatures.add(next_signature)
                if benign_infrastructure_family:
                    queued_benign_infrastructure_families.add(normalized_family_label)

        if getattr(sample, 'learn_signature', None) != next_signature:
            sample.learn_signature = next_signature
            changed = True
        if getattr(sample, 'learn_eligible', False) != next_eligible:
            sample.learn_eligible = next_eligible
            changed = True
        next_weight = compute_learning_weight(sample, next_reason, next_eligible)
        if float(getattr(sample, 'learn_weight', 0.0) or 0.0) != next_weight:
            sample.learn_weight = next_weight
            changed = True
        if getattr(sample, 'learn_reason', None) != next_reason:
            sample.learn_reason = next_reason
            changed = True

    return changed


def prune_redundant_learning_samples(samples: Iterable) -> list:
    ordered = list(samples)
    if not ordered:
        return ordered

    latest_by_event_id: dict[str, int] = {}
    duplicate_found = False
    for idx, sample in enumerate(ordered):
        event_id = str(getattr(sample, 'event_id', '') or '').strip()
        if not event_id:
            continue
        if event_id in latest_by_event_id:
            duplicate_found = True
        latest_by_event_id[event_id] = idx

    if not duplicate_found:
        return ordered

    compacted: list = []
    for idx, sample in enumerate(ordered):
        event_id = str(getattr(sample, 'event_id', '') or '').strip()
        if event_id and latest_by_event_id.get(event_id) != idx:
            continue
        compacted.append(sample)
    return compacted
