#!/usr/bin/env python3
"""Assert the recordings directory of a SIPREC session holds WAV files.

usage: srs_check_recordings.py <base_dir> <session_id> <expected_count>

The session's directory is named by siphon's own storage key, never by the
SRC's session_id, so it is found through the metadata.json siphon writes
beside the audio. Prints each file with its size. Exits non-zero unless exactly
one directory holds that session, it is not named after the session_id, it
holds exactly the expected number of stream-<index>-<8hex>.wav files, each a
RIFF/WAVE file, and at least one holds audio beyond the header (RTP is sent on
the first stream only).
"""
import json
import pathlib
import re
import sys
import time

base, session, expected = sys.argv[1], sys.argv[2], int(sys.argv[3])


def sessions_named(session):
    """The directories whose metadata.json records this session_id."""
    found, unreadable = [], []
    for metadata in sorted(pathlib.Path(base).glob("*/metadata.json")):
        try:
            record = json.loads(metadata.read_text())
        except (OSError, ValueError) as error:
            unreadable.append(f"{metadata} is unreadable: {error}")
            continue
        if record.get("session_id") == session:
            found.append(metadata.parent)
    return found, unreadable


# The record is stored once the engine has closed every file, which can trail
# the BYE by up to siphon's 10 s close wait.
deadline = time.monotonic() + 20
while True:
    matches, problems = sessions_named(session)
    if matches or time.monotonic() > deadline:
        break
    time.sleep(1)
if len(matches) != 1:
    problems.append(f"expected one directory for session {session} in {base}, found {len(matches)}")
directory = matches[0] if len(matches) == 1 else pathlib.Path(base) / "<none>"
if directory.name == session:
    problems.append(f"directory is named after the SRC's session_id: {directory}")
print(f"SRS-DIRECTORY {directory.name}")
files = sorted(directory.glob("*.wav")) if directory.is_dir() else []
pattern = re.compile(r"^stream-\d+-[0-9a-f]{8}\.wav$")
largest = 0
for path in files:
    size = path.stat().st_size
    largest = max(largest, size)
    print(f"SRS-RECORDING {path.name} {size} bytes")
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
