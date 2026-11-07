# What each check does, and what it cannot see

Every finding in a report has the same three parts: **what was detected**, **what that establishes**, and **what remains unknown**. Each carries one *evidence class*. There are no scores or percentages anywhere, because none of these checks has been statistically calibrated.

| Class | Meaning | Can it drive a verdict? |
|-------|---------|-------------------------|
| **Established** | Supported by a trusted original the examiner supplied, or by valid cryptographic evidence | → *Confirmed change* |
| **Indicator** | An anomaly that needs human review; **not** proof of manipulation | → *Suspicious indicators* |
| **Information** | Context, e.g. which software produced the file | never |
| **Limitation** | Something that could not be examined; *blocking* limitations stop the engine saying "no indicators" | → *Inconclusive* if blocking |

Category rules (`VerdictEngine`, four lines, fully visible): any Established → **Confirmed change**; else any Indicator → **Suspicious indicators**; else any blocking Limitation → **Inconclusive**; else **No indicators detected** — which always states that authenticity is *not* established. There is deliberately no "genuine" / "verified" outcome.

Thresholds below are the constants in the code at ruleset `2026.11-r1`; they are fixed, not tuned per file.

## 1. Metadata and creation tool

| Check | Class | Notes / blind spots |
|-------|-------|---------------------|
| Info dictionary + XMP read (XMP with a DOCTYPE/ENTITY is **never parsed**) | info | Metadata is self-asserted; absent ≠ clean |
| Software labels → Word processor / PDF editor / converter / generator / scanner / signing service | info | Each clue ships a caution ("use of this tool does not indicate alteration"). Matching is by name patterns only |
| Creator ≠ Producer (more than one stage) | info | Very common and legitimate |
| Producer is a whole-file rewriter (Ghostscript, iLovePDF, …) after a different authoring tool | **blocking limitation** | Earlier incremental history cannot survive such a rewrite; states "unavailable", not "clean" |
| ModDate earlier than CreationDate | indicator | A clock error is a benign cause |
| Date more than 36 h in the future | indicator | |
| Info vs XMP disagree (producer, creator tool, title, author; dates by > 60 s) | indicator | Benign: a tool updated only one store. Concerning: hand-edited metadata. The file cannot say which |
| Malformed date; unparseable XMP | indicator | |
| XMP history / conversion events, DocumentID ≠ OriginalDocumentID | info | A claim by the file, easily removed or edited |
| Trailer `/ID[0]` changes between revisions | indicator | Some editors regenerate it on every save |

## 2. Revisions and structure

| Check | Class | Notes / blind spots |
|-------|-------|---------------------|
| Incremental updates enumerated; each earlier revision is reconstructed byte-for-byte | info | Verified: revision 0 of an edited file equals the original (`FixtureExpectationsTest`) |
| Object-level diff per update (new / replaced / freed / rewritten-identical), attributed to pages | info or indicator | Indicator only when page content, existing images, pages, fonts, forms or overlay annotations changed. The earlier version is part of the *same untrusted file*, so this is not an independent original |
| Single revision | info | "No history" is **not** evidence of no editing: a regenerated PDF looks identical |
| Cross-reference offsets do not match object positions / xref unusable and rebuilt | indicator | Hex-editing causes this; so do buggy generators and damaged transfers. A same-length byte edit leaves **no** trace (pinned by a test) |
| Objects present in the file but listed in no xref section; data after the final `%%EOF` | indicator | Rolled-back or truncated updates, leftovers |
| Unreferenced objects (page content / images with a recovered-text preview) | indicator for page-like, info otherwise | LibreOffice leaves unreferenced tagged-PDF elements routinely; rated information |
| Linearisation length mismatch | indicator, or info if updates explain it | |
| Same typeface embedded as several subsets on one page | indicator | Editors do it; so do merge tools |
| Encrypted file | **blocking limitation** | Structure examined, strings and streams not |

## 3. Content, paint order and positions (PdfBox-Android)

| Check | Class | Threshold | Blind spots |
|-------|-------|-----------|-------------|
| Text under a later opaque rectangle/image (judged per glyph) | indicator | ≥ 60 % of a glyph covered | Redaction boxes and masks look the same. Covered text is **recovered and reported** |
| Hidden text: invisible render mode, font < 1.5 pt, white on a non-dark background | indicator | | Accessibility layers; OCR text on scans is information instead |
| Visible text / opaque patch drawn over a scanned page | indicator | scan = image ≥ 60 % of page | Page numbers, Bates stamps, signature fields |
| Words set in more than one font | indicator if a digit is involved, else info | | Fallback fonts, drop caps |
| Same-size text on one line at slightly different baselines | indicator | 0.25–1.5 pt offset, same font size | A careful editor aligns exactly (`Fb` is detected only by luck of its editor's placement) |
| Page composition: vector / scanned / scanned with text | info | | No OCR |

Words are rebuilt from order-aware glyphs (gap > 0.18 em starts a new word); glyphs hidden under a later cover are dropped one-for-one so text typed over a white-out is kept. Vertical or rotated text is not reassembled, and multi-column pages are read across columns.

## 4. Comparison with a trusted original

Inputs (all **user-asserted**; every result says the tool cannot verify them): an authenticated PDF, `.docx` or image; a hash (MD5/SHA-1/SHA-256/SHA-512 by length); a verified issuer record.

* **File bytes and document meaning are two separate conclusions.** A re-saved or converted file changes every byte but not the wording. When all comparable layers match, the finding is *information* ("bytes differ, no difference in meaning found") — never a confirmed change.
* **Established:** a text difference (Myers diff over normalised tokens, typed as name / date / amount / number), an entity difference, a different embedded picture, an issuer-record field that disagrees, a page-count difference, a hash-only mismatch (byte level only; the report says meaning is not assessed).
* **Indicator only:** pixel differences in rendered pages (alignment search ±10 px, blur, difference > 48 grey levels, 12 px cells with ≥ 6 % changed pixels). Re-rendering and re-scanning also change pixels, so these are for human review. When the text is identical and the differences are widespread, they are reported as information (typography changed).
* Entities are heuristic: names are recognised **only after labels** such as "Received from:"; numeric dates like 03/04/2024 keep both readings; a number is an amount only with a currency, decimals, a thousands separator or an amount-like label.
* Pictures: perceptual hash distance ≤ 5 of 64 and colour difference ≤ 10 → same picture; > 12 or colour difference > 30 → different; between → similar, review. A changed region inside an otherwise matching picture → locally different. Page-sized scans are judged by the rendered comparison instead.
* A `.docx` original is compared by text, entities and embedded pictures (not rendered pages). Tracked changes inside the reference are reported.
* No OCR: scanned pages are never compared as text.

## 5. Digital signatures (BouncyCastle, provider passed explicitly)

Reported as four separate statements: **1 integrity**, **2 certificate trust**, **3 changes after signing**, **4 a valid signature does not show the content is true**.

* `ByteRange` validated: starts at 0, in-bounds, ordered, the unsigned gap is **exactly** the `/Contents` value (anything else could hide content), coverage of the signing revision. Irregular → indicator and no "valid" claim.
* CMS verification for `adbe.pkcs7.detached`, `ETSI.CAdES.detached`, `adbe.pkcs7.sha1` and RFC 3161 document timestamps. Verified with the bare public key so that **certificate validity is never mixed into cryptographic validity**.
* Digest mismatch → **Established** (cryptographic evidence that signed bytes changed). Accidental corruption is stated as an equally possible cause.
* Certificate trust against a **named** trust set (device store on Android): trusted / unknown root / self-signed / chain incomplete / not valid at signing time. Unknown roots are *not* "invalid": AATL and EU trust lists are not in the device store.
* Signing time: the signer's claim (`/M`, signingTime) is labelled as a claim unless a signature timestamp is verified (imprint and TSA signature checked).
* Revocation: only CRL/OCSP **embedded** in the signature or DSS. The app has no network permission and never queries a responder; otherwise "unknown".
* Changes after signing are classified from the revision diff: further signatures / validation data, form fill, annotation, overlay annotation, new supporting resources, visible content, metadata. **Established only if the signature itself verifies**, so the signed version is cryptographically anchored. DocMDP level is applied (P=1 forbids even annotations). New fonts/appearance streams alone are not "page content".
* Validated against **pyHanko** (an independent implementation) on ten fixtures; each verdict matches its ground truth. An earlier version of this classifier wrongly flagged legitimate co-signing; the test now pins the correct behaviour.

Not supported: `adbe.x509.rsa_sha1`, online revocation, certificate policies, ESS signing-certificate binding, long-term-validation chain building beyond the embedded data.

## 6. Images and scans (traditional methods only; **no machine learning**)

| Check | Class | Blind spots |
|-------|-------|-------------|
| JPEG structure: quantisation tables (IJG-standard quality recognised), sampling, Exif/COM, bytes after EOI | info; trailing data = indicator | Tables show only the **last** compression |
| Editor traces (Exif Software, Photoshop block, known editors) | info | Innocent re-saving is common |
| Images on one page with different JPEG settings | info | A scan plus a photographed signature looks the same |
| Separate image drawn over a page scan (+ resolution ratio > 1.5×) | indicator | Stamps/signatures/logos |
| Noise consistency: 16 px blocks, MAD residual, page median ≥ 0.9, block < 0.30 × median, ≥ 6 blocks, enclosed, not on the border | indicator | **Only works where grain survives compression and the forger added none.** Denoised/whitened scans are reported "not informative", never "clean". Small patches with typed text inside are partly masked by glyph edges |

**Evaluated and rejected: error-level analysis.** Implemented with detail-stratified baselines and agreement across three qualities, it flagged 28–34 regions on *every* scan including unedited controls, so it was removed.
The noise grid was changed from 32 px to 16 px after inspecting one edited fixture (`Gh`); the false-positive rate of this check is therefore only checked on a handful of controls.

Not implemented: double-JPEG / DCT-coefficient analysis, JPEG block-grid misalignment, resampling and clone detection, OCR, any ML detector. If ML is ever added it must be optional, off by default, and independently validated; the product is designed to be fully useful without it.

## 7. Evidence the engine will not give

* Proof that a PDF went through PDF → Word → PDF.
* Original history of a regenerated PDF.
* Any statement that a document, signature, hash match or issuer record shows the *information is true*.
* Anything about the original contents when no trusted original is supplied.

See [BENCHMARK.md](BENCHMARK.md) for what was measured, including every miss.
