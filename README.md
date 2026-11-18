# lib-copyright

Poor man's copyright + **active adversarial AI music copyright protection**.

Bridges passive cryptographic proof-of-existence (OpenTimestamps / Merkle taxonomy trees) with active audio defense (psychoacoustic adversarial cloaking against AI music trainers + survivable spread-spectrum provenance watermarking).

---

## Architecture

### 1. `sh/` — Runnable Prototypes & CLI Scripts
- **[sh/prototype_protect_wav.0.py](sh/prototype_protect_wav.0.py)** — End-to-end Adversarial AI Music Protection & Watermark tool:
  1. **Multi-Layer Hashing (`unique` + `compile`):** Computes exact `SHA-256`, a 256-bit **Perceptual Spectral Fingerprint** (log-energy contour across 32 sub-bands), and compiles your [Taxonomy.def](lib/tax/Taxonomy.def) + [UniversalLocation](lib/universe/d/location.def) into a deterministic **Merkle Root**.
  2. **Psychoacoustic Adversarial Cloak (`cloak`):** Models the human ear's 24-band **Zwicker Bark simultaneous masking threshold** and runs Spectral Projected Gradient Descent (PGD) + micro-phase group-delay perturbation beneath the masking curve. Disrupts log-mel and cepstral representations used by AI audio codecs/trainers while staying transparent to human listeners (~24–26 dB SNR).
  3. **Survivable CDMA Watermark (`embed` & `verify`):** Uses **Informed Subspace Projection (ISP)** over 64 orthonormal Walsh-Hadamard CDMA carriers in the 850 Hz – 4.2 kHz mid-band to embed a 64-bit slice of the Taxonomy Merkle root directly into the audio waveform. Survives mono downmixing, gain normalization, and additive noise with **64/64 (100%) bit recovery** (> 40$\sigma$ detection confidence).
- **[sh/opentimestamps/timestamp.0.py](sh/opentimestamps/timestamp.0.py)** — Anchors file hashes to the Bitcoin blockchain via OpenTimestamps (`.ots` proofs).

### 2. `lib/` — Core Specification & Batch Architecture (Go / Spec)
- **[lib/op/](lib/op/README.md)** — Pipeline operations:
  - [unique.def](lib/op/unique.def) -> [compile.def](lib/op/compile.def) -> [protect.def](lib/op/protect.def) -> [seal.def](lib/op/seal.def) -> [stor.def](lib/op/stor.def) -> [request.def](lib/op/request.def)
- **[lib/tax/](lib/tax/Taxonomy.def)** — Hierarchical copyright & [Legal AI opt-out](lib/tax/d/legal/Legal.def) taxonomy.
- **[lib/hash/](lib/hash/d/README.md)** — Path-hash compilation across author, publisher, jurisdiction, perceptual attributes, and cryptographic proofs.
- **[lib/universe/](lib/universe/d/location.def)** — Spatiotemporal coordinate vector binding.

---

## Quick Start

```bash
# Run the self-contained synthesis, adversarial cloak, watermark & attack survival demo:
python sh/prototype_protect_wav.0.py --demo

# Protect a master WAV file (outputs <track>.protected.wav + <track>.copyright.json):
python sh/prototype_protect_wav.0.py protect my_track.wav --author "Matt" --key "your-secret-key"

# Verify a suspect or re-encoded WAV file against your secret key & manifest:
python sh/prototype_protect_wav.0.py verify my_track.protected.wav --manifest my_track.copyright.json --key "your-secret-key"
```
