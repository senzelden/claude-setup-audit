#!/usr/bin/env python3
"""Read-only local pilot measurement against a reviewed corpus; no model calls."""
import argparse
import json
import clarity


def evaluate(corpus):
    counts = dict(true_positive=0, false_positive=0, false_negative=0, true_negative=0)
    results = []
    for case in corpus['cases']:
        predicted = bool(clarity.candidates(case['text']))
        expected = case['review_label']
        name = ('true_' if predicted == expected else 'false_') + ('positive' if predicted else 'negative')
        counts[name] += 1
        results.append(dict(id=case['id'], candidate=predicted, review_label=expected, classification=name))
    return dict(cases=len(results), counts=counts, results=results,
                limitation='Small author-reviewed development corpus; not a general accuracy estimate.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus')
    args = parser.parse_args()
    with open(args.corpus, encoding='utf-8') as stream:
        result = evaluate(json.load(stream))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
