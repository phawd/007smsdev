#!/usr/bin/env python3
"""
Sequential thinking helper for Project0 using Serena/LLM API and caching.
"""

import hashlib
import os
import json
import requests


CACHE_DIR = os.path.join(os.path.dirname(__file__), 'seq_cache')
os.makedirs(CACHE_DIR, exist_ok=True)

# Serena/LLM API config
SERENA_API_URL = os.environ.get('SERENA_API_URL')  # e.g., 'https://serena.example.com/api/seqthink'
SERENA_API_TOKEN = os.environ.get('SERENA_API_TOKEN')


def cache_key(prompt):
    return hashlib.sha256(prompt.encode()).hexdigest()


def cached_seqthink(prompt):
    key = cache_key(prompt)
    cache_path = os.path.join(CACHE_DIR, key + '.json')
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            return json.load(f)
    if not SERENA_API_URL or not SERENA_API_TOKEN:
        result = {'error': 'SERENA_API_URL or SERENA_API_TOKEN not set', 'result': f'Sequential thinking for: {prompt} (no API call)'}
    else:
        headers = {'Authorization': f'Bearer {SERENA_API_TOKEN}', 'Content-Type': 'application/json'}
        payload = {'prompt': prompt}
        try:
            resp = requests.post(SERENA_API_URL, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            result = resp.json()
        except Exception as e:
            result = {'error': str(e), 'result': f'Sequential thinking for: {prompt} (API error)'}
    with open(cache_path, 'w') as f:
        json.dump(result, f)
    return result


if __name__ == '__main__':
    import sys
    print(cached_seqthink(' '.join(sys.argv[1:])))
