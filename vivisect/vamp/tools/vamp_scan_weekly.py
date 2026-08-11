#!/usr/bin/env python3
"""
VAMP Weekly Sig Scanner

Scans Ubuntu package archives for newer versions of tracked libraries,
downloads them, generates VAMP signatures, and prepares a PR with the
new/updated sig databases for https://github.com/vivisect/vivisect.

This script is designed to run as a weekly cron job. It:
1. Checks the Ubuntu package archive for new versions of tracked libraries
2. Downloads any new/updated .deb packages
3. Generates VAMP sigs using gen_elf_sigs.py
4. Commits changes to a new branch on the fork
5. Creates a PR against vivisect/vivisect

Usage:
    python3 vamp_scan_weekly.py [--dry-run]
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

# --- Configuration ---

# Repos
FORK_REPO = 'git@github.com:aragorn-1337/vivisect.git'
UPSTREAM_REPO = 'https://github.com/vivisect/vivisect.git'
BRANCH_PREFIX = 'vamp-sig-update'

# Package archive URLs
SECURITY_URL = 'http://security.ubuntu.com/ubuntu/pool/main'
ARCHIVE_URL = 'http://archive.ubuntu.com/ubuntu/pool/main'
PORTS_URL = 'http://ports.ubuntu.com/ubuntu-ports/pool/main'

# Libraries to track: (source_package, package_name_pattern, arch, platform, library_name, version_extract_regex)
TRACKED_LIBS = [
    # glibc x64
    ('g/glibc', 'libc6', 'amd64', 'linux', 'glibc', None, SECURITY_URL),
    ('g/glibc', 'libc6-i386', 'amd64', 'linux', 'glibc', None, SECURITY_URL),  # i386 libs in amd64 package
    # glibc arm64
    ('g/glibc', 'libc6', 'arm64', 'linux', 'glibc', None, PORTS_URL),
    # glibc armhf
    ('g/glibc', 'libc6', 'armhf', 'linux', 'glibc', None, PORTS_URL),
    # musl x64
    ('m/musl', 'musl', 'amd64', 'linux', 'musl', None, ARCHIVE_URL),
    # OpenSSL x64
    ('o/openssl', 'libssl3t64', 'amd64', 'linux', 'openssl', None, SECURITY_URL),
    ('o/openssl', 'libssl3', 'amd64', 'linux', 'openssl', None, SECURITY_URL),
    ('o/openssl', 'libssl1.1', 'amd64', 'linux', 'openssl', None, SECURITY_URL),
    # OpenSSL arm64
    ('o/openssl', 'libssl3t64', 'arm64', 'linux', 'openssl', None, PORTS_URL),
    ('o/openssl', 'libssl1.1', 'arm64', 'linux', 'openssl', None, PORTS_URL),
    # zlib
    ('z/zlib', 'zlib1g', 'amd64', 'linux', 'zlib', None, SECURITY_URL),
    # zstd
    ('z/zstd', 'libzstd1', 'amd64', 'linux', 'zstd', None, SECURITY_URL),
    # SQLite
    ('s/sqlite3', 'libsqlite3-0', 'amd64', 'linux', 'sqlite', None, SECURITY_URL),
    # libcurl
    ('c/curl', 'libcurl4', 'amd64', 'linux', 'libcurl', None, SECURITY_URL),
    # liblzma
    ('x/xz-utils', 'liblzma5', 'amd64', 'linux', 'liblzma', None, SECURITY_URL),
    # libbz2
    ('b/bzip2', 'libbz2-1.0', 'amd64', 'linux', 'libbz2', None, SECURITY_URL),
    # liblz4
    ('l/lz4', 'liblz4-1', 'amd64', 'linux', 'liblz4', None, SECURITY_URL),
    # snappy
    ('s/snappy', 'libsnappy1v5', 'amd64', 'linux', 'snappy', None, ARCHIVE_URL),
]

# Output directory for sig files
VAMP_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'vivisect', 'vamp', 'data')

# Working directory for downloads
WORK_DIR = tempfile.mkdtemp(prefix='vamp-scan-')


def fetch_package_listings(source_dir, base_url):
    """Fetch available .deb files from a package directory."""
    url = f'{base_url}/{source_dir}/'
    try:
        req = urllib.request.urlopen(url, timeout=30)
        html = req.read().decode('utf-8', errors='ignore')
        debs = re.findall(r'href="([^"]+\.deb)"', html)
        return debs
    except Exception as e:
        print(f'  ERROR fetching {url}: {e}')
        return []


def find_latest_version(debs, pkg_pattern, arch):
    """Find the latest version .deb for a given package pattern and arch."""
    matching = [d for d in debs if pkg_pattern in d and arch in d and 'dbg' not in d and 'dev' not in d]
    if not matching:
        return None
    # Sort by filename — later versions sort last
    return sorted(matching)[-1]


def download_deb(url, dest_dir):
    """Download a .deb file."""
    fname = os.path.basename(url)
    dest_path = os.path.join(dest_dir, fname)
    try:
        urllib.request.urlretrieve(url, dest_path)
        return dest_path
    except Exception as e:
        print(f'  ERROR downloading {url}: {e}')
        return None


def extract_deb(deb_path, dest_dir):
    """Extract a .deb package."""
    os.makedirs(dest_dir, exist_ok=True)
    subprocess.run(['dpkg-deb', '-x', deb_path, dest_dir],
                   capture_output=True, timeout=30)
    # Find the main .so file
    so_files = []
    for root, dirs, files in os.walk(dest_dir):
        for f in files:
            if f.startswith('lib') and '.so' in f:
                so_files.append(os.path.join(root, f))
    return so_files


def generate_sigs(so_path, library, version, arch, platform, output_path):
    """Generate VAMP sigs from a .so file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cmd = [
        sys.executable,
        os.path.join(script_dir, 'gen_elf_sigs.py'),
        '--input', so_path,
        '--library', library,
        '--version', version,
        '--arch', arch,
        '--platform', platform,
        '--output', output_path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(f'  gen_elf_sigs FAILED: {result.stderr[:200]}')
        return False
    return True


def get_version_from_deb_name(deb_name, pkg_pattern):
    """Extract version string from .deb filename."""
    # e.g., libc6_2.39-0ubuntu8.8_amd64.deb -> 2.39
    parts = deb_name.split('_')
    if len(parts) >= 2:
        version = parts[1].split('-')[0].split('~')[0].split('+')[0]
        return version
    return 'unknown'


def main():
    dry_run = '--dry-run' in sys.argv

    print(f'VAMP Weekly Sig Scanner')
    print(f'Work dir: {WORK_DIR}')
    print(f'Output dir: {VAMP_DATA_DIR}')
    print(f'Dry run: {dry_run}')
    print()

    # Load current index to see what we already have
    index_path = os.path.join(VAMP_DATA_DIR, 'index.json')
    current_versions = {}
    if os.path.exists(index_path):
        with open(index_path) as f:
            idx = json.load(f)
        for s in idx.get('sig_sets', []):
            key = (s['library'], s['arch'], s['platform'])
            current_versions[key] = s['version']

    updates = []
    new_sigs = []

    for source_dir, pkg_pattern, arch, platform, library, _, base_url in TRACKED_LIBS:
        print(f'Checking {library} ({arch}/{platform})...')
        debs = fetch_package_listings(source_dir, base_url)
        if not debs:
            continue

        latest = find_latest_version(debs, pkg_pattern, arch)
        if not latest:
            print(f'  No package found for {pkg_pattern} {arch}')
            continue

        version = get_version_from_deb_name(latest, pkg_pattern)
        key = (library, arch, platform)

        # Check if we already have this version
        current = current_versions.get(key)
        if current and current == version:
            print(f'  Already have {library} {version} ({arch}) — skipping')
            continue

        print(f'  NEW: {library} {version} ({arch}) — was {current or "none"}')
        updates.append((library, version, arch, platform, latest, source_dir, base_url))

    if not updates:
        print('\nNo updates found. All sig databases are current.')
        return

    print(f'\n{len(updates)} libraries to update:')
    for lib, ver, arch, plat, deb, _, _ in updates:
        print(f'  {lib} {ver} {arch}/{plat}')

    if dry_run:
        print('\nDry run — not downloading or generating sigs.')
        return

    # Download and generate sigs
    for library, version, arch, platform, deb_name, source_dir, base_url in updates:
        print(f'\nProcessing {library} {version} ({arch})...')
        deb_url = f'{base_url}/{source_dir}/{deb_name}'
        deb_path = download_deb(deb_url, WORK_DIR)
        if not deb_path:
            continue

        extract_dir = os.path.join(WORK_DIR, f'extract-{library}-{version}-{arch}')
        so_files = extract_deb(deb_path, extract_dir)
        if not so_files:
            print(f'  No .so files found in package')
            continue

        # Generate sigs for each .so
        for so_path in so_files:
            if 'crypto' in os.path.basename(so_path):
                lib_name = 'openssl'
                out_name = f'openssl_{version.replace(".", "_")}_{arch}_{platform}_crypto.json'
            elif 'ssl' in os.path.basename(so_path) and 'libssl' in os.path.basename(so_path):
                lib_name = 'openssl-ssl'
                out_name = f'openssl-ssl_{version.replace(".", "_")}_{arch}_{platform}.json'
            else:
                lib_name = library
                out_name = f'{library}_{version.replace(".", "_")}_{arch}_{platform}.json'

            out_path = os.path.join(VAMP_DATA_DIR, out_name)
            print(f'  Generating sigs from {os.path.basename(so_path)}...')
            if generate_sigs(so_path, lib_name, version, arch, platform, out_path):
                new_sigs.append(out_path)
                print(f'  OK: {out_name}')

    # Update index
    if new_sigs:
        print('\nUpdating index...')
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, script_dir)
        # Also need vivisect on path
        sys.path.insert(0, os.path.join(script_dir, '..', '..'))
        import vivisect.vamp as v_vamp
        idx = v_vamp.updateSigSetIndex()
        print(f'Index updated: {len(idx["sig_sets"])} sig sets')

        # Commit and push
        print('\nCommitting changes...')
        repo_dir = os.path.join(script_dir, '..', '..')
        branch_name = f'{BRANCH_PREFIX}-{hashlib.md5(str(sorted(new_sigs)).encode()).hexdigest()[:8]}'

        subprocess.run(['git', 'checkout', 'master'], cwd=repo_dir, capture_output=True)
        subprocess.run(['git', 'pull', 'origin', 'master'], cwd=repo_dir, capture_output=True)
        subprocess.run(['git', 'checkout', '-b', branch_name], cwd=repo_dir, capture_output=True)
        subprocess.run(['git', 'add', 'vivisect/vamp/data/'], cwd=repo_dir, capture_output=True)
        subprocess.run(['git', 'commit', '-m',
                        f'VAMP sig update: {len(new_sigs)} new/updated sig sets\n\n'
                        f'Auto-generated by weekly VAMP sig scanner.\n'
                        f'Updated: {", ".join(os.path.basename(s) for s in new_sigs)}'],
                       cwd=repo_dir, capture_output=True)
        subprocess.run(['git', 'push', 'origin', branch_name], cwd=repo_dir, capture_output=True)

        print(f'\nPushed branch: {branch_name}')
        print(f'PR link: https://github.com/aragorn-1337/vivisect/pull/new/{branch_name}')

    print(f'\nDone. {len(new_sigs)} sig files updated.')


if __name__ == '__main__':
    main()