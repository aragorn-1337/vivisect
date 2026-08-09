"""
Generic VAMP signature analysis module.

This module checks each function against all loaded VAMP signature sets
(not just MSVC) and marks matches as thunks with the signature name.

Unlike vivisect.analysis.ms.msvc which only checks MSVC sigs, this module
auto-loads all JSON sig sets from vamp/data/ that match the workspace's
architecture and platform.
"""
import logging
import os

import envi.bytesig as e_bytesig

import vivisect.vamp as v_vamp

logger = logging.getLogger(__name__)

# Cache: (arch, platform) -> SignatureTree
_sigtree_cache = {}


def _get_sigtree(arch, platform):
    """Load and cache all matching sig sets for the given arch/platform."""
    cache_key = (arch, platform)
    if cache_key in _sigtree_cache:
        return _sigtree_cache[cache_key]

    tree = e_bytesig.SignatureTree()

    # Load all available sig sets
    sig_sets = v_vamp.loadAllSigSets()
    loaded = 0
    for sig_tree, meta, filepath in sig_sets:
        sig_arch = meta.get('arch', '')
        sig_platform = meta.get('platform', '')

        # Match by architecture (handle aliases)
        arch_match = _arch_matches(sig_arch, arch)
        # If no platform specified in workspace, load everything
        platform_match = (not platform or not sig_platform or
                          sig_platform == platform or
                          sig_platform == 'all')

        if arch_match and platform_match:
            # Merge this tree's sigs into our combined tree
            for bytekey in sig_tree.sigs:
                # The sigs dict keys are bytes+masks concatenated
                # We need to extract the original sig info
                # Since we can't easily get it back, re-load from the file
                pass
            loaded += 1

    # Since merging trees is awkward, just load all matching files directly
    tree = e_bytesig.SignatureTree()
    data_dir = os.path.join(os.path.dirname(v_vamp.__file__), 'data')
    if os.path.isdir(data_dir):
        import json
        import binascii
        for fname in sorted(os.listdir(data_dir)):
            if not fname.endswith('.json') or fname == 'index.json':
                continue
            filepath = os.path.join(data_dir, fname)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                sig_arch = data.get('arch', '')
                sig_platform = data.get('platform', '')
                if not _arch_matches(sig_arch, arch):
                    continue
                if platform and sig_platform and sig_platform != platform:
                    continue
                for sig in data.get('signatures', []):
                    bytez = binascii.unhexlify(sig['bytes'])
                    mask = binascii.unhexlify(sig['mask']) if sig.get('mask') else None
                    tree.addSignature(bytez, masks=mask, val=sig['name'])
                loaded += 1
            except Exception:
                continue

    logger.debug("Loaded %d sig sets for arch=%s platform=%s", loaded, arch, platform)
    _sigtree_cache[cache_key] = tree
    return tree


def _arch_matches(sig_arch, vw_arch):
    """Check if a signature set's architecture matches the workspace's."""
    if not sig_arch or not vw_arch:
        return True  # Be permissive if either is unknown

    # Normalize architecture names
    arch_aliases = {
        'i386': {'i386', 'x86', 'ia32', 'i486', 'i586', 'i686'},
        'amd64': {'amd64', 'x64', 'x86_64', 'x86-64'},
        'arm': {'arm', 'arm32', 'aarch32'},
        'aarch64': {'aarch64', 'arm64'},
    }

    sig_arch_lower = sig_arch.lower()
    vw_arch_lower = vw_arch.lower()

    # Direct match
    if sig_arch_lower == vw_arch_lower:
        return True

    # Check aliases
    for canonical, aliases in arch_aliases.items():
        if sig_arch_lower in aliases and vw_arch_lower in aliases:
            return True

    return False


def analyzeFunction(vw, funcva):
    """
    Check a function against all loaded VAMP signature sets.
    If a match is found, mark the function as a thunk and name it.
    """
    arch = vw.getMeta('Architecture', '')
    platform = vw.getMeta('Platform', '')

    tree = _get_sigtree(arch, platform)
    if not tree.sigs:
        return

    offset, bytes_data = vw.getByteDef(funcva)
    match = tree.getSignature(bytes_data, offset=offset)
    if match is not None:
        fname = match.split(".")[-1]
        vw.makeName(funcva, "%s_%.8x" % (fname, funcva), filelocal=True)
        vw.makeFunctionThunk(funcva, match)


def analyze(vw):
    """
    Workspace-level analysis entry point.
    Called during the analysis pass to initialize the VAMP sig module.
    """
    arch = vw.getMeta('Architecture', '')
    platform = vw.getMeta('Platform', '')
    logger.info("VAMP generic analysis: loading sigs for arch=%s platform=%s", arch, platform)
    # Pre-load the sig tree
    tree = _get_sigtree(arch, platform)
    logger.info("VAMP generic analysis: %d signatures loaded", len(tree.sigs))