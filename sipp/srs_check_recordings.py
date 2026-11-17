#!/usr/bin/env python3
"""Assert the recordings directory of a SIPREC session holds WAV files.

usage: srs_check_recordings.py <base_dir> <session_id> <expected_count>

Prints each file with its size. Exits non-zero unless exactly the expected
number of stream-<index>-<8hex>.wav files exist, each a RIFF/WAVE file, and at
least one holds audio beyond the header (RTP is sent on the first stream only).
"""
import pathlib
import re
import sys

base, session, expected = sys.argv[1], sys.argv[2], int(sys.argv[3])
directory = pathlib.Path(base) / session
files = sorted(directory.glob("*.wav")) if directory.is_dir() else []
pattern = re.compile(r"^stream-\d+-[0-9a-f]{8}\.wav$")
largest = 0
for path in files:
    size = path.stat().st_size
    largest = max(largest, size)
    print(f"SRS-RECORDING {path.name} {size} bytes")
problems = []
if len(files) != expected:
    problems.append(f"expected {expected} wav files in {directory}, found {len(files)}")
for path in files:
    if not pattern.match(path.name):
        problems.append(f"unexpected file name {path.name}")
    if path.read_bytes()[:4] != b"RIFF":
        problems.append(f"{path.name} is not a RIFF file")
if files and largest <= 44:
    problems.append("no wav holds audio beyond the 44-byte header")
if problems:
    for problem in problems:
        print("SRS-CHECK FAIL:", problem)
    sys.exit(1)
print(f"SRS-CHECK OK: {len(files)} wav files, largest {largest} bytes")
