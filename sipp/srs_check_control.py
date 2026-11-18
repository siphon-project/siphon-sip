#!/usr/bin/env python3
"""Assert the WAV files a SIPREC control-rail case left in the recordings volume.

usage: srs_check_control.py <directory | session=<session_id>> <expected_files> <channels>

A directory the application chose is named as is. A session recorded into
siphon's default layout is named `session=<session_id>`: its directory carries
siphon's own storage key, never the SRC's session_id, so it is found through
the metadata.json beside the audio (stored once every file is closed, which
can trail the BYE by up to siphon's 10 s close wait).

Exits non-zero unless the directory holds exactly the expected number of RIFF/WAVE
files, each with the wanted channel count in its fmt chunk, and at least one holds
audio beyond the 44-byte header.
"""
import json
import pathlib
import struct
import sys
import time

BASE = pathlib.Path("/recordings")


def session_directory(session):
    """The one directory whose metadata.json records this session_id."""
    deadline = time.monotonic() + 20
    while True:
        found = []
        for metadata in sorted(BASE.glob("*/metadata.json")):
            try:
                if json.loads(metadata.read_text()).get("session_id") == session:
                    found.append(metadata.parent)
            except (OSError, ValueError):
                continue
        if found or time.monotonic() > deadline:
            break
        time.sleep(1)
    if len(found) != 1:
        print(f"SRS-CONTROL-CHECK FAIL: expected one directory for session {session}, found {len(found)}")
        sys.exit(1)
    if found[0].name == session:
        print(f"SRS-CONTROL-CHECK FAIL: directory is named after the SRC's session_id: {found[0]}")
        sys.exit(1)
    return found[0]


target, expected, channels = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
if target.startswith("session="):
    directory = session_directory(target.removeprefix("session="))
else:
    directory = pathlib.Path(target)
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
