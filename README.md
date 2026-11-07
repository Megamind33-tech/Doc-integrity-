# Doc Forensics

An Android app that helps a person **investigate** whether a PDF may have been edited, converted or altered. It extracts demonstrable facts, separates them from indicators and from unsupported conclusions, and exports a reproducible evidence report.

It does **not** certify documents and does **not** promise universal fraud detection. Every report states what was detected, what that establishes, and what remains unknown. No percentages or confidence scores are produced anywhere.

## The four report categories

| Category | Means |
|----------|-------|
| **Confirmed change** | Supported by a trusted original the examiner supplied, or by valid cryptographic evidence |
| **Suspicious indicators** | Anomalies requiring review; *not* proof of fraud |
| **No indicators detected** | No supported signs found — **authenticity is not established** |
| **Inconclusive** | Insufficient or unavailable evidence (encrypted, unreadable reference, history known to be discarded) |

The "no indicators" category is slate blue, never green, and there is no "genuine" or "verified" outcome by design.

## What it examines

1. **Metadata and creation tool** — Info/XMP, dates, Info-vs-XMP conflicts, tool labels (Word, LibreOffice, PDF editors, converters, scanners). A label is context, never proof of falsification.
2. **Revisions and structure** — incremental updates reconstructed **byte-for-byte**, object-level diff per update, xref integrity, hidden/unreferenced objects, linearisation, fonts, trailing data.
3. **Content** — text covered by later shapes (and recovered), hidden text, text/patches over scans, mixed fonts, baseline offsets.
4. **Comparison with a trusted original** — PDF, `.docx`, image, hash or issuer record: hashes, text, names, dates, amounts, document numbers, embedded photographs and rendered pages, with highlighted regions and a side-by-side view. *Changed bytes* and *changed meaning* are separate conclusions.
5. **Digital signatures** — ByteRange, CMS verification, certificate trust, signing time, embedded revocation evidence and what changed **after** signing. A valid signature over false content is reported as valid, not as true.
6. **Images and scans** — JPEG structure, images placed over scans, noise consistency. Traditional methods only; no machine learning, so the product is fully useful with AI absent.
7. **Report** — premium on-device report screen; exportable **PDF evidence report** (with the findings JSON attached) and a standalone JSON export.

Details and blind spots of every check: [docs/DETECTION.md](docs/DETECTION.md).
What was measured, **including every miss**: [docs/BENCHMARK.md](docs/BENCHMARK.md) (generated from live engine runs and guarded by a test).

## Privacy and preservation

* Analysis runs **locally**. The app declares **no `INTERNET` permission**; nothing is uploaded and online certificate-revocation lookups are not performed.
* The examined file is read into memory and **never modified**; hashes are taken from the original bytes. A test pins that analysis leaves input bytes unchanged.
* Files are picked with the system document picker (read access to exactly that file). Exports go to a location *you* choose.
* The only temporary files (for `PdfRenderer`) are app-private, owner-only (0600), randomly named, **zero-wiped** on completion, on reset and at start-up.
* `FLAG_SECURE` keeps documents out of screenshots and the recents thumbnail; `allowBackup=false`.
* Reports record SHA-256/512/SHA-1/MD5 of the file and the tool, ruleset, PDF-library and crypto-library versions; the JSON never contains the document's bytes.
* Anti-misuse: the PDF report is titled and footed "not a certificate of authenticity", and the engine has no output that says a document is genuine.

## Build and test

Requirements: JDK 17+ (built with 21), Android SDK (platform 36, build-tools 35). `local.properties` with `sdk.dir`, or `ANDROID_HOME`.

```bash
./gradlew :forensics:testDebugUnitTest :app:testDebugUnitTest   # 187 tests (JVM + Robolectric native graphics)
./gradlew :app:assembleDebug                                      # app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:assembleRelease                                    # R8-minified, unsigned
```

`poppler-utils` (`pdftoppm`) is used by the rendered-comparison tests and the benchmark; those tests skip when it is absent.

### Fixtures and benchmark

All test documents come from **real tools**, never hand-faked artefacts; the generators are in `tools/fixtures/` (LibreOffice round trips, PyMuPDF edits, Pillow/img2pdf scans, pyHanko signatures with a throw-away CA). Signature fixtures were validated against pyHanko's own validator first.

```bash
python3 tools/fixtures/generate_fixtures.py --out forensics/src/test/resources/fixtures --work /tmp/fx
python3 tools/fixtures/generate_extra.py   --dir forensics/src/test/resources/fixtures
python3 tools/fixtures/generate_scans.py   --dir forensics/src/test/resources/fixtures --work /tmp/fx
python3 tools/fixtures/generate_signed.py  --dir forensics/src/test/resources/fixtures
./gradlew :forensics:testDebugUnitTest --tests '*BenchmarkTest*' -Dbenchmark.write=true   # regenerate docs/BENCHMARK.md
```

## Layout

```
forensics/   analysis engine (Android library, no UI)
  pdf/raw        tolerant PDF parser: xref tables/streams, revisions, object streams
  pdf/analysis   metadata, tool fingerprints, revisions, structure
  pdf/content    paint-order scanner, glyph-based words, content indicators
  compare        text/entity/picture/visual comparison, DOCX reader
  sig            ByteRange, CMS verification, trust, revocation, post-signing changes
  image          JPEG inspector, noise analysis
  report         verdict-independent JSON + PDF evidence report
  engine         orchestration and the four-category verdict
app/         Compose UI, SAF I/O, secure temp files, PdfRenderer
tools/fixtures   fixture generators      docs/   detection notes and benchmark
```

## Evidence in this repository

* `dist/doc-forensics-0.1.0-debug.apk` (+ `SHA256SUMS`): the debug-signed APK built from this commit. No `INTERNET` permission (`aapt2 dump permissions`).
* `docs/screenshots/`: the real Compose screens rendered by Robolectric native graphics (not from a device): a confirmed-change report, a no-indicators report, the trusted-original setup screen, and a tall signed-and-edited report.
* `docs/samples/`: PDF evidence reports exported by the app's own report builder (re-opened and checked in `ReportExportTest`; each carries `report.json` as an attachment).
* `docs/BENCHMARK.md`: 31 scenarios + reference variants, with every false negative and false positive.

## Known limits (summary)

* Microsoft Word was not available when this was built: Word round trips were produced with LibreOffice. Word-specific tool labels are tested at string level.
* The APK was built and inspected with the SDK tools (`aapt2` permissions, `apksigner`), and its UI was exercised with Robolectric (including real rendered screenshots), but it was **never installed or run**: no emulator or device was available. `PdfRenderer` page rendering, the SAF pickers/exports and the R8 release build were therefore not executed on Android.
* Without a trusted original, edits that leave no structural trace (a name or amount changed in a Word round trip, a regenerated PDF, a same-quality re-saved scan, a validly signed false document) cannot be detected. See the benchmark.
* The benchmark is small and author-constructed: it shows what each mechanism can and cannot see, not accuracy rates.
