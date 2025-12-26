#!/usr/bin/env python3
"""
Web search helper for Project0 using Apify and caching.
"""
import requests
import hashlib
import os
import json

CACHE_DIR = os.path.join(os.path.dirname(__file__), 'web_cache')
os.makedirs(CACHE_DIR, exist_ok=True)

import os
APIFY_TOKEN = os.environ.get('APIFY_TOKEN')
APIFY_SEARCH_URL = 'https://api.apify.com/v2/actor-tasks/apify~web-scraper/run-sync-get-dataset-items'


def cache_key(query):
    return hashlib.sha256(query.encode()).hexdigest()


def cached_search(query):
    key = cache_key(query)
    cache_path = os.path.join(CACHE_DIR, key + '.json')
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            return json.load(f)
    if not APIFY_TOKEN:
        data = {'error': 'APIFY_TOKEN not set', 'result': f'Web search for: {query} (no API call)'}
    else:
        params = {
            'token': APIFY_TOKEN,
            'limit': 3,
            'search': query
        }
        try:
            resp = requests.get(APIFY_SEARCH_URL, params=params, timeout=20)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            data = {'error': str(e), 'result': f'Web search for: {query} (API error)'}
    with open(cache_path, 'w') as f:
        json.dump(data, f)
    return data


if __name__ == '__main__':
    import sys
    print(cached_search(' '.join(sys.argv[1:])))
