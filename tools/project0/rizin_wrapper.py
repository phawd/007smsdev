#!/usr/bin/env python3
"""
Simple Rizin wrapper: call rizin CLI for symbols/strings. Falls back to readelf/strings.
"""
import subprocess


def rizin_strings(path):
    try:
        out = subprocess.check_output(
            ['rizin', '-q', '-c', 'iz', '-c', 'q', path], stderr=subprocess.DEVNULL)
        return out.decode(errors='ignore')
    except Exception:
        try:
            out = subprocess.check_output(
                ['strings', path], stderr=subprocess.DEVNULL)
            return out.decode(errors='ignore')
        except Exception:
            return ''


def rizin_symbols(path):
    try:
        out = subprocess.check_output(
            ['rizin', '-q', '-c', 'is', '-c', 'q', path], stderr=subprocess.DEVNULL)
        return out.decode(errors='ignore')
    except Exception:
        try:
            out = subprocess.check_output(
                ['readelf', '-s', path], stderr=subprocess.DEVNULL)
            return out.decode(errors='ignore')
        except Exception:
            return ''
