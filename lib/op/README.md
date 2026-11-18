# Operations (`lib/op`)

Core pipeline operations for `lib-copyright`:

1. **[unique.def](unique.def)** — Extract exact (`SHA-256`) and perceptual (`256-bit spectral contour`) hashes from masters and stems.
2. **[compile.def](compile.def)** — Compile entity metadata, jurisdiction, universal coordinates, and asset hashes into a deterministic Taxonomy Merkle root and 64-bit watermark payload.
3. **[protect.def](protect.def)** — Active audio defense: inject psychoacoustically masked adversarial perturbations (`cloak`) to poison AI feature extractors + embed a survivable 64-bit CDMA spread-spectrum watermark (`embed`).
4. **[seal.def](seal.def)** — Sign and anchor the compiled bundle and protected master to OpenTimestamps (`.ots`).
5. **[stor.def](stor.def)** — Vault the clean master + keys locally (`stor.0`) and publish the protected master.
6. **[request.def](request.def)** — Extract the watermark and perceptual hash from suspect/scraped audio to prove provenance.
