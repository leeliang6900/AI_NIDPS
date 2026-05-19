from __future__ import annotations

import argparse
import ipaddress
from typing import Any, Dict, Optional

from online_learning_policy import (
    apply_learning_policy,
    prune_redundant_learning_samples,
    should_hold_for_review,
)
from online_store import OnlineSampleStore

STORE = OnlineSampleStore()
FAMILY_FIELDS = (
    'family_label',
    'display_label',
    'family_confidence',
    'family_source',
    'novelty_score',
)
INFRASTRUCTURE_SAFE_ATTACK_MAX = 0.18
INFRASTRUCTURE_SAFE_MALWARE_MAX = 0.18

KNOWN_RULE_FAMILIES = {
    'PORT_SCAN': ('attack.port_scan', 'Port Scan', 'high', 'known_rule', 0.05),
    'ICMP_FLOOD': ('attack.icmp_flood', 'ICMP Flood', 'high', 'known_rule', 0.05),
    'TCP_FLOOD': ('attack.tcp_flood', 'TCP Flood', 'high', 'known_rule', 0.05),
    'UDP_FLOOD': ('attack.udp_flood', 'UDP Flood', 'high', 'known_rule', 0.05),
    'HTTP_FLOOD': ('attack.http_flood', 'HTTP Flood', 'high', 'known_rule', 0.05),
    'CONN_FLOOD': ('attack.conn_flood', 'Connection Flood', 'high', 'known_rule', 0.05),
    'SSH_BRUTE_FORCE': ('attack.bruteforce.ssh', 'SSH Brute Force', 'high', 'known_rule', 0.05),
    'FTP_BRUTE_FORCE': ('attack.bruteforce.ftp', 'FTP Brute Force', 'high', 'known_rule', 0.05),
    'TELNET_BRUTE_FORCE': ('attack.bruteforce.telnet', 'Telnet Brute Force', 'high', 'known_rule', 0.05),
    'RDP_BRUTE_FORCE': ('attack.bruteforce.rdp', 'RDP Brute Force', 'high', 'known_rule', 0.05),
    'WINBOX_BRUTE_FORCE': ('attack.bruteforce.winbox', 'Winbox Brute Force', 'high', 'known_rule', 0.05),
    'SUSP_HIGH_PORT': ('attack.high_port_suspicious', 'High-Port Suspicious Traffic', 'medium', 'known_rule', 0.20),
    'CRYPTO_MINER': ('malware.crypto_miner', 'Crypto Miner', 'high', 'known_rule', 0.05),
    'C2_BACKDOOR': ('malware.c2_backdoor', 'C2 Backdoor', 'high', 'known_rule', 0.05),
    'RANSOMWARE_PRECHECK': ('malware.ransomware_precheck', 'Ransomware Precheck', 'high', 'known_rule', 0.05),
    'DNS_TUNNEL': ('malware.dns_tunnel', 'DNS Tunnel', 'high', 'known_rule', 0.05),
    'DATA_EXFIL': ('malware.data_exfil', 'Data Exfiltration', 'high', 'known_rule', 0.05),
    'C2_BEACON': ('malware.c2_beacon', 'C2 Beacon', 'high', 'known_rule', 0.05),
    'OBS_PING': ('benign.observed.ping', 'Observed Ping', 'high', 'known_rule', 0.02),
    'OBS_SSH': ('benign.observed.ssh', 'Observed SSH', 'high', 'known_rule', 0.02),
}

def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except Exception:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except Exception:
        return False


def is_broadcast_like_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except Exception:
        return False
    if ip.version == 4 and str(ip).endswith('.255'):
        return True
    return ip.is_multicast


def num(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def primary_score(preferred: Any, fallback: Any) -> float:
    if preferred not in (None, ''):
        return num(preferred)
    return num(fallback)


def family_payload(
    family_label: str,
    display_label: str,
    confidence: str,
    source: str,
    novelty_score: float,
) -> Dict[str, Any]:
    return {
        'family_label': family_label,
        'display_label': display_label,
        'family_confidence': confidence,
        'family_source': source,
        'novelty_score': round(float(novelty_score), 3),
    }


def merge_payloads(*payloads: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for payload in payloads:
        if payload:
            merged.update(payload)
    return merged


def is_manual_label_source(value: Any) -> bool:
    source = str(value or '').strip()
    return bool(source) and not source.startswith('auto')

# ===================== Family from Rule =====================
def infer_family_from_rule(sample) -> Optional[Dict[str, Any]]:
    decision = str(sample.decision or '').upper()
    rule = str(sample.rule or '').upper()
    mapped = KNOWN_RULE_FAMILIES.get(rule)
    if mapped:
        family_label, display_label, confidence, source, novelty = mapped
        return family_payload(family_label, display_label, confidence, source, novelty)

    if decision == 'SUPPRESSED_VICTIM_LEG':
        return family_payload('benign.victim_leg', 'Victim Response Leg', 'high', 'known_rule', 0.02)
    return None
# ===================== End =====================

# ===================== Family from behavior =====================
def infer_family_from_behavior(sample) -> Dict[str, Any]:
    feat = sample.features or {}
    decision = str(sample.decision or '').upper()
    category = str(sample.category or '').upper()
    rule = str(sample.rule or '').upper()
    src_private = is_private_ip(sample.src)
    dst_private = is_private_ip(sample.dst)
    dst_broadcast = is_broadcast_like_ip(sample.dst)

    proto_mode = int(num(feat.get('proto_mode')))
    flows = num(feat.get('flows'))
    uniq_dports = num(feat.get('uniq_dports'))
    pkts_rate = num(feat.get('pkts_rate'))
    bytes_rate = num(feat.get('bytes_rate'))
    top_port_ratio = num(feat.get('top_port_ratio'))
    well_known_ratio = num(feat.get('well_known_ratio'))
    dport_entropy = num(feat.get('dport_entropy'))
    top_is_22 = num(feat.get('top_is_22'))
    top_is_53 = num(feat.get('top_is_53'))
    icmp_is_proto = num(feat.get('icmp_is_proto'))
    top_is_67 = num(feat.get('top_is_67'))
    top_is_68 = num(feat.get('top_is_68'))
    top_is_123 = num(feat.get('top_is_123'))
    top_is_miner = num(feat.get('top_is_miner'))
    top_is_backdoor = num(feat.get('top_is_backdoor'))

    atk = primary_score(sample.xgb_attack_score, sample.online_attack_score)
    mal = primary_score(sample.xgb_malware_score, sample.online_malware_score)

    if top_is_miner >= 1.0:
        return family_payload('malware.miner_like', 'Miner-Like Activity', 'medium', 'behavior_heuristic', 0.72)

    if top_is_backdoor >= 1.0:
        return family_payload('malware.backdoor_like', 'Backdoor-Like Activity', 'medium', 'behavior_heuristic', 0.72)

    if top_is_22 >= 1.0 and uniq_dports <= 2 and flows >= 5:
        novelty = 0.55 if rule == 'SSH_BRUTE_FORCE' else 0.78
        return family_payload('attack.bruteforce.ssh_like', 'SSH Brute Force Like', 'medium', 'behavior_heuristic', novelty)

    if icmp_is_proto >= 1.0 and pkts_rate >= 20:
        return family_payload('attack.icmp_surge_like', 'ICMP Surge Like', 'medium', 'behavior_heuristic', 0.70)

    if uniq_dports >= 8 and dport_entropy >= 1.5 and flows >= 10:
        return family_payload('attack.port_sweep_like', 'Port Sweep Like', 'medium', 'behavior_heuristic', 0.76)

    if proto_mode == 17 and dst_broadcast and flows <= 5 and well_known_ratio >= 0.5 and decision == 'OBSERVED':
        return family_payload('benign.broadcast_discovery_like', 'Broadcast Discovery', 'medium', 'behavior_heuristic', 0.68)

    if decision == 'OBSERVED' and proto_mode == 17 and (top_is_67 >= 1.0 or top_is_68 >= 1.0):
        if src_private and dst_private and flows <= 6 and uniq_dports <= 2:
            return family_payload('benign.infrastructure.dhcp', 'DHCP Traffic', 'medium', 'behavior_heuristic', 0.06)

    if decision == 'OBSERVED' and top_is_53 >= 1.0:
        if flows <= 12 and uniq_dports <= 3 and top_port_ratio >= 0.5 and (src_private or dst_private):
            return family_payload('benign.infrastructure.dns', 'DNS Query Traffic', 'medium', 'behavior_heuristic', 0.08)

    if decision == 'OBSERVED' and proto_mode == 17 and top_is_123 >= 1.0:
        if flows <= 5 and uniq_dports <= 2:
            return family_payload('benign.infrastructure.ntp', 'Time Sync Traffic', 'medium', 'behavior_heuristic', 0.08)

    if category == 'OBSERVED' and src_private and dst_private and proto_mode == 17 and flows <= 5 and top_port_ratio >= 0.5:
        return family_payload('benign.internal_service_like', 'Internal Service-Like Traffic', 'low', 'behavior_heuristic', 0.56)

    if mal >= 0.85 and bytes_rate >= 250:
        return family_payload('malware.unknown_behavior_like', 'Unknown Malware-Like Activity', 'medium', 'behavior_heuristic', 0.84)

    if atk >= 0.80 or decision.startswith('BLOCKED'):
        return family_payload('attack.unknown_suspicious_like', 'Unknown Suspicious Attack-Like Traffic', 'medium', 'behavior_heuristic', 0.82)

    if src_private and dst_private:
        return family_payload('benign.unknown_internal_like', 'Unknown Internal Traffic', 'low', 'behavior_heuristic', 0.60)

    return family_payload('unknown.unclassified', 'Unclassified Traffic', 'low', 'behavior_heuristic', 0.92)
# ===================== End =====================

def infer_family_annotation(sample) -> Dict[str, Any]:
    return merge_payloads(
        infer_family_from_behavior(sample),
        infer_family_from_rule(sample),
    )


def auto_label_from_local_signals(sample) -> Optional[Dict[str, Any]]:
    decision = str(sample.decision or '').upper()
    rule = str(sample.rule or '').upper()
    category = str(sample.category or '').upper()
    atk = primary_score(sample.xgb_attack_score, sample.online_attack_score)
    mal = primary_score(sample.xgb_malware_score, sample.online_malware_score)
    src_private = is_private_ip(sample.src)
    dst_private = is_private_ip(sample.dst)
    blocked_like = decision.startswith('BLOCKED') or decision == 'ALREADY_BLOCKED_OR_NEVER'
    family = infer_family_annotation(sample)

    local_attack_rules = {
        'PORT_SCAN',
        'ICMP_FLOOD',
        'TCP_FLOOD',
        'UDP_FLOOD',
        'HTTP_FLOOD',
        'CONN_FLOOD',
        'SSH_BRUTE_FORCE',
        'FTP_BRUTE_FORCE',
        'TELNET_BRUTE_FORCE',
        'RDP_BRUTE_FORCE',
        'WINBOX_BRUTE_FORCE',
        'SUSP_HIGH_PORT',
    }
    local_malware_rules = {
        'CRYPTO_MINER',
        'C2_BACKDOOR',
        'RANSOMWARE_PRECHECK',
        'DNS_TUNNEL',
        'DATA_EXFIL',
        'C2_BEACON',
    }

    if decision == 'OBSERVED' and rule in {'OBS_PING', 'OBS_SSH'} and src_private and dst_private:
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 0,
            'label_source': 'auto_local_observed_safe',
            'confidence': 'high',
        })

    if decision == 'SUPPRESSED_VICTIM_LEG':
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 0,
            'label_source': 'auto_local_victim_leg_safe',
            'confidence': 'high',
        })

    if blocked_like:
        if category == 'MALWARE' and (rule in local_malware_rules or mal >= 0.75):
            return merge_payloads(family, {
                'attack_label': 0,
                'malware_label': 1,
                'label_source': 'auto_local_blocked_malware',
                'confidence': 'high',
            })
        if category == 'ATTACK' and (rule in local_attack_rules or atk >= 0.75):
            return merge_payloads(family, {
                'attack_label': 1,
                'malware_label': 0,
                'label_source': 'auto_local_blocked_attack',
                'confidence': 'high',
            })

    if category == 'MALWARE' and rule in local_malware_rules and mal >= 0.85:
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 1,
            'label_source': 'auto_local_high_conf_malware',
            'confidence': 'medium',
        })

    if category == 'ATTACK' and rule in local_attack_rules and atk >= 0.90:
        return merge_payloads(family, {
            'attack_label': 1,
            'malware_label': 0,
            'label_source': 'auto_local_high_conf_attack',
            'confidence': 'medium',
        })
    return None


def auto_label_from_behavior(sample) -> Optional[Dict[str, Any]]:
    family = infer_family_annotation(sample)
    family_label = str(family.get('family_label') or '')
    decision = str(sample.decision or '').upper()
    src_private = is_private_ip(sample.src)
    dst_private = is_private_ip(sample.dst)
    atk = primary_score(sample.xgb_attack_score, sample.online_attack_score)
    mal = primary_score(sample.xgb_malware_score, sample.online_malware_score)
    feat = sample.features or {}
    flows = num(feat.get('flows'))
    infra_scores_safe = atk <= INFRASTRUCTURE_SAFE_ATTACK_MAX and mal <= INFRASTRUCTURE_SAFE_MALWARE_MAX

    if family_label == 'benign.broadcast_discovery_like' and decision == 'OBSERVED':
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 0,
            'label_source': 'auto_family_broadcast_safe',
            'confidence': 'medium',
        })

    if family_label in {'benign.infrastructure.dhcp', 'benign.infrastructure.dns', 'benign.infrastructure.ntp'} and decision == 'OBSERVED' and infra_scores_safe:
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 0,
            'label_source': 'auto_family_infrastructure_safe',
            'confidence': 'medium',
        })

    if family_label == 'benign.internal_service_like' and decision == 'OBSERVED' and src_private and dst_private and atk < 0.35 and mal < 0.35:
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 0,
            'label_source': 'auto_family_internal_service_safe',
            'confidence': 'low',
        })

    if family_label in {'attack.bruteforce.ssh', 'attack.bruteforce.ssh_like'} and (flows >= 20 or atk >= 0.50 or decision.startswith('BLOCKED')):
        return merge_payloads(family, {
            'attack_label': 1,
            'malware_label': 0,
            'label_source': 'auto_family_bruteforce_like',
            'confidence': 'medium',
        })

    if family_label == 'attack.port_sweep_like' and atk >= 0.60:
        return merge_payloads(family, {
            'attack_label': 1,
            'malware_label': 0,
            'label_source': 'auto_family_portsweep_like',
            'confidence': 'medium',
        })

    if family_label in {'malware.miner_like', 'malware.backdoor_like', 'malware.unknown_behavior_like'} and mal >= 0.75:
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 1,
            'label_source': 'auto_family_malware_like',
            'confidence': 'medium',
        })

    if family_label == 'attack.unknown_suspicious_like' and atk >= 0.85:
        return merge_payloads(family, {
            'attack_label': 1,
            'malware_label': 0,
            'label_source': 'auto_family_attack_like',
            'confidence': 'medium',
        })

    if family_label.startswith('malware.'):
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 1,
            'label_source': 'auto_family_default_malware',
            'confidence': 'low',
        })

    if family_label.startswith('attack.'):
        return merge_payloads(family, {
            'attack_label': 1,
            'malware_label': 0,
            'label_source': 'auto_family_default_attack',
            'confidence': 'low',
        })

    if family_label.startswith('benign.'):
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 0,
            'label_source': 'auto_family_default_benign',
            'confidence': 'low',
        })

    if decision.startswith('BLOCKED') or str(sample.category or '').upper() == 'ATTACK' or atk >= 0.30:
        return merge_payloads(family, {
            'attack_label': 1,
            'malware_label': 1 if mal >= max(0.55, atk) else 0,
            'label_source': 'auto_family_unknown_attack',
            'confidence': 'low',
        })

    if str(sample.category or '').upper() == 'MALWARE' or mal >= 0.55:
        return merge_payloads(family, {
            'attack_label': 0,
            'malware_label': 1,
            'label_source': 'auto_family_unknown_malware',
            'confidence': 'low',
        })

    return merge_payloads(family, {
        'attack_label': 0,
        'malware_label': 0,
        'label_source': 'auto_family_unknown_benign',
        'confidence': 'low',
    })

# ===================== Auto Label =====================
def auto_label_sample(sample) -> Optional[Dict[str, Any]]:
    return auto_label_from_local_signals(sample) or auto_label_from_behavior(sample)
# ===================== End =====================

def apply_family(sample, payload: Dict[str, Any]) -> bool:
    changed = False
    for field in FAMILY_FIELDS:
        value = payload.get(field)
        if value is None:
            continue
        if getattr(sample, field, None) == value:
            continue
        setattr(sample, field, value)
        changed = True
    return changed


def apply_binary_labels(sample, payload: Dict[str, Any]) -> bool:
    if 'attack_label' not in payload and 'malware_label' not in payload:
        return False
    attack_label = payload.get('attack_label')
    malware_label = payload.get('malware_label')
    if attack_label is None and malware_label is None:
        return False
    sample.attack_label = attack_label
    sample.malware_label = malware_label
    sample.label_source = str(payload.get('label_source', 'auto'))
    review_only = should_hold_for_review(sample)
    sample.label_status = 'candidate' if review_only else 'labeled'
    sample.learn_eligible = not review_only
    sample.learn_weight = 0.0
    sample.learn_reason = 'review_candidate' if review_only else 'awaiting_policy_refresh'
    sample.trained = False
    return True

# ===================== Auto Label Pending =====================
def auto_label_pending(limit: int = 0) -> Dict[str, Any]:
    all_samples = list(STORE.iter_samples() or [])
    labeled = 0
    review_candidates = 0
    attack_positive = 0
    malware_positive = 0
    family_annotated = 0
    processed = 0
    by_source: Dict[str, int] = {}
    changed_any = False

    for sample in all_samples:
        result = auto_label_sample(sample)
        if not result:
            continue

        if apply_family(sample, result):
            family_annotated += 1
            changed_any = True

        if sample.trained or is_manual_label_source(sample.label_source):
            continue
        if limit > 0 and processed >= limit:
            continue

        processed += 1
        source = str(result.get('label_source', 'auto'))
        if apply_binary_labels(sample, result):
            changed_any = True
            labeled += 1
            if sample.label_status == 'candidate':
                review_candidates += 1
            attack_positive += int(result.get('attack_label') or 0)
            malware_positive += int(result.get('malware_label') or 0)
            by_source[source] = by_source.get(source, 0) + 1

    if apply_learning_policy(all_samples):
        changed_any = True

    pruned_samples = prune_redundant_learning_samples(all_samples)
    if len(pruned_samples) != len(all_samples):
        all_samples = pruned_samples
        changed_any = True

    if changed_any:
        STORE.rewrite_preserving_new_samples(all_samples)

    return {
        'processed': processed,
        'labeled': labeled,
        'review_candidates': review_candidates,
        'attack_positive': attack_positive,
        'malware_positive': malware_positive,
        'family_annotated': family_annotated,
        'sources': by_source,
    }
# ===================== End =====================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Auto-label pending online-learning samples using local behavior inference and high-confidence signals.')
    parser.add_argument('--limit', type=int, default=0, help='Maximum number of pending samples to inspect. 0 means all.')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = auto_label_pending(args.limit)
    print(f"Processed pending samples: {result['processed']}")
    print(f"Auto-labeled samples: {result['labeled']}")
    print(f"Review candidates: {result['review_candidates']}")
    print(f"Attack positive labels: {result['attack_positive']}")
    print(f"Malware positive labels: {result['malware_positive']}")
    print(f"Family annotations updated: {result['family_annotated']}")
    if result['sources']:
        print('Label sources:')
        for source, count in result['sources'].items():
            print(f'  - {source}: {count}')


if __name__ == '__main__':
    main()
