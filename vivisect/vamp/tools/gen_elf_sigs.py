#!/usr/bin/env python3
"""
Fast VAMP Signature Generator for ELF libraries.

This script generates VAMP signatures directly from ELF shared libraries
using the ELF symbol table + raw byte extraction, bypassing the slow full
vivisect analysis pipeline. It uses the vivisect Elf parser for symbol
extraction and relocation info, then reads raw bytes and masks relocations
to produce byte/mask signatures.

This is orders of magnitude faster than the full gen_sigs.py which runs
complete vivisect analysis on each library.

Usage:
    python3 vamp/tools/gen_elf_sigs.py \
        --input /lib/x86_64-linux-gnu/libc.so.6 \
        --library glibc \
        --version 2.39 \
        --arch amd64 \
        --platform linux \
        --compiler gcc-13 \
        --output vamp/data/glibc_2.39_x64.json
"""

import argparse
import binascii
import hashlib
import json
import os
import struct
import sys
import time

# Add vivisect to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from Elf import Elf


def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_reloc_offsets(elf):
    """
    Get a set of RVA values that have relocations.
    Returns a dict mapping rva -> reloc_size (pointer size in bytes).
    """
    relocs = {}
    psize = 8 if elf.bits == 64 else 4
    try:
        reloc_list = elf.getRelocs()
        for parent, reloc in reloc_list:
            try:
                r_offset = reloc.vsGetField('r_offset').vsGetValue()
                relocs[r_offset] = psize
            except Exception:
                continue
    except Exception:
        pass
    return relocs


def get_func_symbols(elf):
    """
    Extract function symbols from the ELF dynamic symbol table.
    Returns list of (rva, size, name) tuples.
    """
    func_syms = []
    try:
        dynsyms = elf.getDynSyms()
        for s in dynsyms:
            try:
                if s.getInfoType() != 2:  # STT_FUNC
                    continue
                rva = s.vsGetField('st_value').vsGetValue()
                size = s.vsGetField('st_size').vsGetValue()
                name = s.getName()
                if rva > 0 and size > 0 and name:
                    func_syms.append((rva, size, name))
            except Exception:
                continue
    except Exception:
        pass
    return func_syms


def get_first_linear_block(elf, rva, func_size):
    """
    Read the first linear code block of a function.
    Uses elf.readAtRva to read bytes at the given RVA.

    Returns: (bytes, size) or (None, 0) on failure
    """
    max_read = min(func_size, 256)  # Cap at 256 bytes for sig
    try:
        bytez = elf.readAtRva(rva, max_read)
        return bytez, len(bytez)
    except Exception:
        return None, 0


def mask_relocations(bytez, rva_start, reloc_offsets, psize):
    """
    Mask out relocation slots in the byte sequence.
    Returns (sig_bytes, mask_bytes) with relocatable addresses zeroed.
    """
    sig = bytearray(bytez)
    mask = bytearray(b'\xff' * len(bytez))

    for reloc_rva, reloc_size in reloc_offsets.items():
        # Check if this relocation falls within our byte range
        offset_in_block = reloc_rva - rva_start
        if 0 <= offset_in_block < len(bytez):
            end = min(offset_in_block + psize, len(bytez))
            for i in range(offset_in_block, end):
                sig[i] = 0x00
                mask[i] = 0x00

    return bytes(sig), bytes(mask)


def generate_elf_sigs(input_path, library, version, arch, platform_name,
                      compiler, compiled_flags='', source_url=None,
                      min_length=8, max_masked_ratio=0.50,
                      min_confidence='low', dedup=True):
    """
    Generate VAMP signatures from an ELF shared library.

    Returns: sigset dict ready for JSON serialization.
    """
    binary_sha256 = compute_sha256(input_path)

    # Keep file handle open — Elf needs it for readAtRva
    f = open(input_path, 'rb')
    elf = Elf(f)

    # Determine pointer size
    psize = 8 if elf.bits == 64 else 4

    # Get function symbols
    func_syms = get_func_symbols(elf)
    print(f"Found {len(func_syms)} function symbols")

    # Get relocations
    reloc_offsets = get_reloc_offsets(elf)
    print(f"Found {len(reloc_offsets)} relocations")

    # Generate signatures
    signatures = []
    skipped = 0
    errors = 0

    for rva, func_size, name in sorted(func_syms):
        try:
            bytez, block_size = get_first_linear_block(
                elf, rva, func_size)
            if bytez is None or block_size == 0:
                skipped += 1
                continue

            # Mask relocations
            sig_bytes, mask_bytes = mask_relocations(
                bytez, rva, reloc_offsets, psize)

            # Compute metrics
            masked_count = sum(1 for b in mask_bytes if b == 0)
            masked_ratio = masked_count / block_size if block_size > 0 else 1.0

            # Confidence scoring
            if block_size >= 16 and masked_ratio < 0.25:
                confidence = 'high'
            elif block_size >= 8 and masked_ratio < 0.50:
                confidence = 'medium'
            else:
                confidence = 'low'

            # Filter
            if block_size < min_length:
                skipped += 1
                continue
            if masked_ratio > max_masked_ratio:
                skipped += 1
                continue

            # Strip version info from name (e.g., "printf@@GLIBC_2.2.5" -> "printf")
            clean_name = name.split('@@')[0].split('@')[0]

            sig_entry = {
                'name': '%s.%s' % (library, clean_name),
                'bytes': sig_bytes.hex(),
                'mask': mask_bytes.hex(),
                'func_size': func_size,
                'first_block_size': block_size,
                'reloc_count': masked_count // psize,
                'masked_ratio': round(masked_ratio, 4),
                'confidence': confidence,
            }
            signatures.append(sig_entry)

        except Exception as e:
            errors += 1
            continue

    print(f"Generated {len(signatures)} signatures (skipped {skipped}, errors {errors})")

    # Serialize
    import vivisect.vamp as v_vamp
    sigset = v_vamp.serializeSigSet(
        library=library,
        version=version,
        arch=arch,
        platform=platform_name,
        compiler=compiler,
        compiled_flags=compiled_flags,
        binary_sha256=binary_sha256,
        signatures=signatures,
        source_url=source_url,
    )

    # Deduplicate
    if dedup:
        sigset = v_vamp.dedupSigs(sigset)
        print(f"After dedup: {len(sigset['signatures'])} signatures")
        if sigset.get('dedup_conflicts'):
            print(f"Dedup conflicts: {len(sigset['dedup_conflicts'])}")

    # Clean up file handle
    f.close()

    return sigset


def main():
    parser = argparse.ArgumentParser(
        description='Fast VAMP Signature Generator for ELF libraries')
    parser.add_argument('--input', '-i', required=True, help='Input ELF library (.so)')
    parser.add_argument('--output', '-o', required=True, help='Output JSON signature file')
    parser.add_argument('--library', required=True, help='Library name (e.g., glibc)')
    parser.add_argument('--version', required=True, help='Library version (e.g., 2.39)')
    parser.add_argument('--arch', required=True, help='Architecture (i386, amd64, arm, aarch64)')
    parser.add_argument('--platform', default='linux', help='Platform')
    parser.add_argument('--compiler', default='unknown', help='Compiler')
    parser.add_argument('--flags', default='', help='Compilation flags')
    parser.add_argument('--source-url', help='URL to source/binary')
    parser.add_argument('--min-length', type=int, default=8)
    parser.add_argument('--max-masked', type=float, default=0.50)
    parser.add_argument('--min-confidence', default='low', choices=['low', 'medium', 'high'])
    parser.add_argument('--no-dedup', action='store_true')
    args = parser.parse_args()

    sigset = generate_elf_sigs(
        input_path=args.input,
        library=args.library,
        version=args.version,
        arch=args.arch,
        platform_name=args.platform,
        compiler=args.compiler,
        compiled_flags=args.flags,
        source_url=args.source_url,
        min_length=args.min_length,
        max_masked_ratio=args.max_masked,
        min_confidence=args.min_confidence,
        dedup=not args.no_dedup,
    )

    import vivisect.vamp as v_vamp
    v_vamp.saveSigSet(args.output, sigset)
    print(f"Wrote {len(sigset['signatures'])} signatures to {args.output}")


if __name__ == '__main__':
    main()