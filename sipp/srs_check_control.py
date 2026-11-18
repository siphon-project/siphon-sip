#!/usr/bin/env python3
"""Assert the WAV files a SIPREC control-rail case left in the recordings volume.

usage: srs_check_control.py <directory> <expected_files> <channels>

Exits non-zero unless the directory holds exactly the expected number of RIFF/WAVE
files, each with the wanted channel count in its fmt chunk, and at least one holds
audio beyond the 44-byte header.
"""
import pathlib
import struct
import sys

directory, expected, channels = pathlib.Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
files = sorted(directory.glob("*.wav")) if directory.is_dir() else []
problems = []
largest = 0
for path in files:
    data = path.read_bytes()
    largest = max(largest, len(data))
    found = struct.unpack("<H", data[22:24])[0] if len(data) >= 24 else -1
    print(f"SRS-RECORDING {path.name} {len(data)} bytes, {found} channel(s)")
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        problems.append(f"{path.name} is not a RIFF/WAVE file")
    if found != channels:
        problems.append(f"{path.name} has {found} channels, expected {channels}")
if len(files) != expected:
    problems.append(f"expected {expected} wav files in {directory}, found {len(files)}")
if files and largest <= 44:
    problems.append("no wav holds audio beyond the 44-byte header")
if problems:
    for problem in problems:
        print("SRS-CONTROL-CHECK FAIL:", problem)
    sys.exit(1)
print(f"SRS-CONTROL-CHECK OK: {len(files)} wav files in {directory}, {channels} channel(s), largest {largest} bytes")
