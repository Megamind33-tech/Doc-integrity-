package com.docintegrity.forensics.report

import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.util.Json

/**
 * Machine-readable export of a report. Keys are emitted in a fixed order and nothing here depends on the device, so
 * the same file analysed by the same ruleset yields the same findings (only `tool.analysed_at` differs). It records
 * the file fingerprints and every tool/library version needed to reproduce the analysis. It never contains the
 * examined document's bytes.
 */
object ReportJson {
    const val SCHEMA = "doc-forensics-report/1"

    private fun r2(d: Double) = Math.round(d * 100) / 100.0

    fun toJson(r: ForensicReport): String = Json.obj {
        str("schema", SCHEMA)
        obj("tool") {
            str("name", r.tool.name); str("version", r.tool.version); str("ruleset", r.tool.rulesetVersion)
            str("pdfbox_android", r.tool.pdfboxAndroid); str("bouncy_castle", r.tool.bouncyCastle); str("analysed_at", r.tool.analysedAtIso)
        }
        obj("file") {
            str("name", r.fileName); num("size_bytes", r.hashes.size)
            str("sha256", r.hashes.sha256); str("sha512", r.hashes.sha512); str("sha1", r.hashes.sha1); str("md5", r.hashes.md5)
            bool("is_pdf", r.isPdf); str("pdf_version", r.pdfVersion); num("pages", r.pageCount)
        }
        obj("verdict") {
            str("category", r.verdict.verdict.name); str("label", r.verdict.verdict.label); str("summary", r.verdict.verdict.summary)
            strs("reasons", r.verdict.reasons); strs("limitations", r.verdict.limitations)
            str("note", "No probability or confidence score is computed. This category is not a certification of authenticity.")
        }
        strs("standing_limitations", r.standingLimitations)
        strs("checks_run", r.checksRun)
        str("trust_set", r.trust.description)
        arr("revisions", r.revisions) { v ->
            num("index", v.index); num("start_offset", v.startOffset); num("end_offset", v.endOffset)
            str("sha256_of_this_version", v.prefixSha256); num("objects_changed", v.changes.size)
        }
        arr("signatures", r.signatures) { s ->
            num("index", s.index); str("field", s.fieldName); str("sub_filter", s.subFilter); bool("timestamp_only", s.timestampOnly)
            str("signer", s.signerCn); str("issuer", s.certIssuer); str("serial", s.serialHex)
            str("integrity", s.crypto.name); str("integrity_detail", s.cryptoDetail)
            str("certificate_trust_at_signing", s.trustAtSigning?.status?.name); str("certificate_trust_detail", s.trustAtSigning?.detail)
            str("revocation", s.revocation?.status?.name)
            str("claimed_signing_time", s.claimedTime); str("verified_timestamp", s.verifiedTimestamp?.toInstant()?.toString())
            num("signed_revision", s.signedRevision); num("later_revisions", s.laterRevisions); num("bytes_after_signature", s.bytesAfterSignature)
            strs("byte_range_problems", s.byteRangeProblems)
            strs("changes_after_signing", s.laterChanges.groupBy { it.cls }.map { "${it.key.name}: ${it.value.size}" })
            num("doc_mdp_level", s.docMdp)
        }
        r.comparison?.takeIf { it.referenceKind != null || it.hashChecks.isNotEmpty() }?.let { c ->
            obj("comparison") {
                str("reference_kind", c.referenceKind?.name); str("reference_name", c.referenceName); str("reference_sha256", c.referenceSha256)
                str("file_bytes_identical", c.bytesIdentical.name); str("document_meaning_changed", c.meaningChanged.name)
                bool("text_compared", c.textCompared); num("text_differences", c.textHunks.size)
                strs("entity_differences", c.entityDeltas.map { "${it.type.name}/${it.kind.name}: ${it.label ?: ""} ${it.reference ?: ""} -> ${it.submitted ?: ""}".trim() })
                strs("picture_results", c.images.map { "${it.verdict.name}: ${it.reference ?: "-"} / ${it.submitted ?: "-"}" })
                num("visual_regions", c.visual.sumOf { it.diff.regions.size })
                strs("issuer_fields", c.issuer.map { "${it.field}: ${if (it.matched) "agrees" else "DISAGREES"}" })
                str("note", "Reference material is user-supplied and unverified by this tool.")
            }
        }
        arr("findings", r.findings) { f ->
            str("id", f.id); str("area", f.area.name); str("evidence_class", f.evidence.name); bool("blocking_limitation", f.blocking)
            str("title", f.title); str("detected", f.detected); str("establishes", f.establishes); str("unknown", f.unknown)
            arr("details", f.details) { d -> str("key", d.first); str("value", d.second) }
            arr("regions", f.regions) { g ->
                num("page", g.page + 1); num("x_pt", r2(g.x)); num("y_pt", r2(g.y)); num("width_pt", r2(g.w)); num("height_pt", r2(g.h))
                str("side", g.side.name); str("label", g.label)
            }
        }
    }
}
