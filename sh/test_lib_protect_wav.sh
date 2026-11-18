#!/usr/bin/env sh
# sh/test_lib_protect_wav.sh
# Verifies:
#   1. test/res/sine_440hz.wav is generated and remains 100% byte-identical after protection
#   2. The diff (protected - clean) is safe for Club / PA speaker systems (zero DC offset,
#      zero infrasonic cone excursion <25 Hz, untouched sub-bass 25-120 Hz, safe HF horns >12 kHz)
#   3. 64/64 CDMA provenance watermark bits are recovered with >5 sigma confidence

set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(dirname -- "$SCRIPT_DIR")"

python "$SCRIPT_DIR/prototype_protect_wav.0.py" --test-sine "$ROOT_DIR/test/res"
