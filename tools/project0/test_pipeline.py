#!/usr/bin/env python3
"""
Test script for Project0 pipeline: scan, analyze, summarize, and report.
Processes the first binary found in the analysis results, uses web and sequential helpers, and prints results.
"""
from sequential_helper import cached_seqthink
from web_helper import cached_search
import json
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

ANALYSIS_JSON = os.path.join(os.path.dirname(
    __file__), '../../analysis/binary_analysis_results.json')


def main():
    with open(ANALYSIS_JSON, encoding='utf-8') as f:
        data = json.load(f)
    if not data['libraries']:
        print('No libraries found in analysis results.')
        return
    # Take the first binary for demonstration
    lib = data['libraries'][0]
    print(f"Analyzing: {lib['path']}")
    # Use web search helper
    web_result = cached_search(lib['path'])
    print("\nWeb search result:")
    print(json.dumps(web_result, indent=2))
    # Use sequential thinking helper
    seq_prompt = f"Summarize the purpose and likely function of {lib['path']} based on its exported symbols: {', '.join(s['name'] for s in lib.get('dynsym', [])[:20])}"
    seq_result = cached_seqthink(seq_prompt)
    print("\nSequential thinking result:")
    print(json.dumps(seq_result, indent=2))


if __name__ == '__main__':
    main()
