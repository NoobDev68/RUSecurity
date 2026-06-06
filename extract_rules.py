import json
import os
import re
from collections import defaultdict, Counter
from frst_parser import (
    parse_frst_report, parse_additional_report, parse_fixlist, match_action_to_entry,
    is_boilerplate_action, normalize_line, generalize_pattern
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAIRS_DIR = os.path.join(SCRIPT_DIR, 'pairs')
OUTPUT_RULES = os.path.join(SCRIPT_DIR, 'rules.json')
FRST_DIR = PAIRS_DIR
ADDITIONAL_DIR = PAIRS_DIR
FIXLIST_DIR = PAIRS_DIR


def extract_triples():
    triples = []
    files = os.listdir(PAIRS_DIR)
    frst_ids = set()
    additional_ids = set()
    fixlist_ids = set()

    for f in files:
        m = re.match(r'FRST_(\d+)\.txt', f)
        if m:
            frst_ids.add(int(m.group(1)))
        m = re.match(r'Additional_(\d+)\.txt', f)
        if m:
            additional_ids.add(int(m.group(1)))
        m = re.match(r'fixlist_(\d+)\.txt', f)
        if m:
            fixlist_ids.add(int(m.group(1)))

    common = frst_ids & additional_ids & fixlist_ids
    for idx in sorted(common):
        triples.append({
            'id': idx,
            'frst': os.path.join(PAIRS_DIR, f'FRST_{idx}.txt'),
            'additional': os.path.join(PAIRS_DIR, f'Additional_{idx}.txt'),
            'fixlist': os.path.join(PAIRS_DIR, f'fixlist_{idx}.txt'),
        })
    return triples


def main():
    triples = extract_triples()
    print(f"Found {len(triples)} complete triples")

    exact_rules = Counter()
    pattern_rules = Counter()
    action_to_sources = defaultdict(list)

    matched = 0
    matched_frst = 0
    matched_additional = 0
    unmatched = 0
    total_actions = 0

    negative_examples = defaultdict(int)

    for triple in triples:
        try:
            report = parse_frst_report(triple['frst'])
            additional_report = parse_additional_report(triple['additional'])
            all_entries = report['entries'] + additional_report['entries']
            fixlist_actions = parse_fixlist(triple['fixlist'])
        except Exception as e:
            print(f"  Error processing triple {triple['id']}: {e}")
            continue

        for action in fixlist_actions:
            if is_boilerplate_action(action):
                continue

            total_actions += 1
            matched_entry = match_action_to_entry(action, all_entries)

            if matched_entry:
                matched += 1
                if matched_entry in report['entries']:
                    matched_frst += 1
                else:
                    matched_additional += 1
                entry_norm = matched_entry['normalized']
                action_norm = normalize_line(action)

                exact_rules[entry_norm] += 1
                action_to_sources[action_norm].append(matched_entry)

                gen_pattern = generalize_pattern(entry_norm)
                if gen_pattern != entry_norm:
                    gen_action = generalize_pattern(action_norm)
                    pattern_rules[(gen_pattern, gen_action)] += 1

                gen_pattern2 = re.sub(r'"[^"]*"', '"..."', entry_norm)
                gen_action2 = re.sub(r'"[^"]*"', '"..."', action_norm)
                if gen_pattern2 != entry_norm:
                    pattern_rules[(gen_pattern2, gen_action2)] += 1
            else:
                unmatched += 1

        for entry in report['entries']:
            in_fixlist = False
            entry_norm = entry['normalized']
            for action in fixlist_actions:
                if is_boilerplate_action(action):
                    continue
                if match_action_to_entry(action, [entry]):
                    in_fixlist = True
                    break
            if not in_fixlist:
                features = (
                    entry['has_caution'],
                    entry['has_no_file'],
                    entry['has_unsigned'],
                    entry['has_missing_driver'],
                    entry['is_mountpoints2'],
                    entry['is_alternate_stream'],
                    entry['is_group_policy'],
                    entry['is_policies'],
                    entry['is_firewall_rule'],
                    entry['is_browser_homepage'],
                    entry['is_browser_startup'],
                    entry['is_browser_search'],
                    entry['is_browser_extension'],
                    entry['is_task_entry'],
                    entry['is_service_entry'],
                    entry['is_run_key'],
                )
                negative_examples[features] += 1

    print(f"\nTotal non-boilerplate actions: {total_actions}")
    print(f"Matched: {matched} (FRST: {matched_frst}, Additional: {matched_additional})")
    print(f"Unmatched: {unmatched}")

    top_exact = exact_rules.most_common(60)
    print(f"\nTop 60 exact rules (by frequency):")
    for pattern, count in top_exact:
        if count >= 3:
            print(f"  [{count:4d}x] {pattern[:100]}")

    all_entries_for_heuristics = []
    for triple in triples[:200]:
        try:
            report = parse_frst_report(triple['frst'])
            additional_report = parse_additional_report(triple['additional'])
            all_entries = report['entries'] + additional_report['entries']
            fixlist = parse_fixlist(triple['fixlist'])
            for entry in all_entries:
                entry['in_fixlist'] = False
                for action in fixlist:
                    if is_boilerplate_action(action):
                        continue
                    if match_action_to_entry(action, [entry]):
                        entry['in_fixlist'] = True
                        break
                all_entries_for_heuristics.append(entry)
        except:
            pass

    feature_stats = defaultdict(lambda: {'malicious': 0, 'benign': 0, 'total': 0})
    for e in all_entries_for_heuristics:
        features = [
            ('has_caution', e['has_caution']),
            ('has_no_file', e['has_no_file']),
            ('has_unsigned', e['has_unsigned']),
            ('is_alternate_stream', e['is_alternate_stream']),
            ('is_firewall_rule', e['is_firewall_rule']),
            ('is_hidden_program', e.get('is_hidden_program', False)),
            ('is_custom_clsid', e.get('is_custom_clsid', False)),
            ('is_browser_homepage', e['is_browser_homepage']),
            ('is_browser_startup', e['is_browser_startup']),
            ('is_browser_search', e['is_browser_search']),
            ('is_task_entry', e['is_task_entry']),
            ('is_service_entry', e['is_service_entry']),
            ('is_run_key', e['is_run_key']),
            ('task_with_caution', e['is_task_entry'] and e['has_caution']),
            ('task_with_nofile', e['is_task_entry'] and e['has_no_file']),
            ('run_key_with_nofile', e['is_run_key'] and e['has_no_file']),
            ('run_key_with_unsigned', e['is_run_key'] and e['has_unsigned']),
            ('firewall_with_nofile', e['is_firewall_rule'] and e['has_no_file']),
        ]
        for name, val in features:
            if val:
                feature_stats[name]['total'] += 1
                if e['in_fixlist']:
                    feature_stats[name]['malicious'] += 1
                else:
                    feature_stats[name]['benign'] += 1

    print(f"\n--- Heuristic feature analysis (from {len(all_entries_for_heuristics)} entries) ---")
    heuristic_rules = []
    for feat_name, stats in sorted(feature_stats.items()):
        if stats['total'] > 0:
            ratio = stats['malicious'] / stats['total'] * 100
            print(f"  {feat_name:40s}: {stats['malicious']:4d}/{stats['total']:4d} ({ratio:5.1f}%) malicious")
            if ratio >= 50 and stats['total'] >= 3:
                heuristic_rules.append({
                    'feature': feat_name,
                    'malicious': stats['malicious'],
                    'total': stats['total'],
                    'ratio': round(ratio, 1),
                })

    rules_output = {
        'metadata': {
            'total_triples_analyzed': len(triples),
            'total_actions_matched': matched,
            'total_actions_unmatched': unmatched,
        },
        'exact_rules': [
            {'pattern': p, 'count': c}
            for p, c in exact_rules.most_common()
            if c >= 2
        ],
        'pattern_rules': [
            {'pattern': p[0], 'action': p[1], 'count': c}
            for p, c in pattern_rules.most_common()
            if c >= 2
        ],
        'heuristic_rules': heuristic_rules,
    }

    with open(OUTPUT_RULES, 'w', encoding='utf-8') as f:
        json.dump(rules_output, f, ensure_ascii=False, indent=2)

    print(f"\nRules saved to {OUTPUT_RULES}")
    print(f"  Exact rules: {len(rules_output['exact_rules'])}")
    print(f"  Pattern rules: {len(rules_output['pattern_rules'])}")
    print(f"  Heuristic rules: {len(heuristic_rules)}")


if __name__ == '__main__':
    main()
