#!/usr/bin/env python3
"""
ELF/shared-library scanner for Project0
Usage: python scanner.py /path/to/dir -o output.json
"""
import os
import json
import argparse
import subprocess
from elftools.elf.elffile import ELFFile


def is_elf(path):
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7fELF'
    except Exception:
        return False


def inspect_elf(path):
    info = {'path': path}
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            hdr = elf.header
            info['type'] = hdr['e_type']
            info['machine'] = hdr['e_machine']
            info['entry'] = hex(hdr['e_entry'])
            # dynsym symbols
            syms = []
            if elf.get_section_by_name('.dynsym'):
                for sym in elf.get_section_by_name('.dynsym').iter_symbols():
                    syms.append(
                        {'name': sym.name, 'bind': sym['st_info']['bind'], 'type': sym['st_info']['type']})
            info['dynsym_count'] = len(syms)
            info['dynsym'] = syms[:200]
    except Exception as e:
        info['error'] = str(e)
    return info


def fallback_readelf(path):
    try:
        out = subprocess.check_output(
            ['readelf', '-h', path], stderr=subprocess.DEVNULL).decode(errors='ignore')
        return out
    except Exception:
        return ''


def run_rizin_extract(path):
    # call rizin if available, fallback to strings
    try:
        out = subprocess.check_output(
            ['rizin', '-q', '-c', 'iz', '-c', 'q', path], stderr=subprocess.DEVNULL).decode(errors='ignore')
        return out
    except Exception:
        try:
            out = subprocess.check_output(
                ['strings', path], stderr=subprocess.DEVNULL).decode(errors='ignore')
            return out
        except Exception:
            return ''


def find_libraries(root):
    results = []
    for dirpath, dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                if is_elf(p):
                    results.append(p)
            except Exception:
                continue
    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument('root')
    p.add_argument('-o', '--output', default='output.json')
    args = p.parse_args()

    libs = find_libraries(args.root)
    summary = {'root': args.root, 'count': len(libs), 'libraries': []}
    for i, lib in enumerate(libs):
        meta = inspect_elf(lib)
        # include brief strings preview
        meta['strings_preview'] = run_rizin_extract(lib)[:2000]
        summary['libraries'].append(meta)
        if i % 20 == 0:
            print(f"Scanned {i}/{len(libs)}: {lib}")

    with open(args.output, 'w') as f:
        json.dump(summary, f, indent=2)
    print('Wrote', args.output)


if __name__ == '__main__':
    main()
