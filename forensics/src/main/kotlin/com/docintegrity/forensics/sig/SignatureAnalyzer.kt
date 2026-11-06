package com.docintegrity.forensics.sig

import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.pdf.analysis.ChangeType
import com.docintegrity.forensics.pdf.analysis.ObjectKind
import com.docintegrity.forensics.pdf.analysis.RevisionInfo
import com.docintegrity.forensics.pdf.raw.PdfArray
import com.docintegrity.forensics.pdf.raw.PdfDict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.pdf.raw.PdfLexer
import com.docintegrity.forensics.pdf.raw.PdfName
import com.docintegrity.forensics.pdf.raw.PdfRef
import com.docintegrity.forensics.pdf.raw.PdfStream
import com.docintegrity.forensics.pdf.raw.PdfString
import com.docintegrity.forensics.pdf.raw.StreamDecoder
import com.docintegrity.forensics.pdf.raw.XrefEntryType
import com.docintegrity.forensics.util.Hashing
import com.docintegrity.forensics.util.PdfDates
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.Time
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignerDigestMismatchException
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.tsp.TimeStampToken
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

enum class CryptoStatus(val label: String) {
    VALID("Cryptographically valid"),
    DIGEST_MISMATCH("Signed bytes do not match the signature"),
    SIGNATURE_INVALID("Signature does not verify"),
    UNSUPPORTED("Could not be verified (unsupported)"),
    MALFORMED("Malformed signature"),
}

enum class PostSignChange(val label: String) {
    SIGNATURE_OR_LTV("further signature or validation data"),
    FORM_FILL("form-field values"),
    ANNOTATION("annotation / markup"),
    ANNOTATION_OVERLAY("overlay annotation (stamp, text box, shape)"),
    SUPPORTING_RESOURCE("new appearance streams, fonts or images (not referenced by page content on their own)"),
    VISIBLE_CONTENT("page content, existing images/fonts/forms, or pages"),
    METADATA("document information / metadata"),
    OTHER("other objects"),
}

class LaterChange(val rev: Int, val cls: PostSignChange, val description: String)

class SignatureResult(
    val index: Int,
    val objNum: Int,
    val fieldName: String?,
    val subFilter: String?,
    val timestampOnly: Boolean,
    val signerCn: String?,
    val certSubject: String?,
    val certIssuer: String?,
    val serialHex: String?,
    val notBefore: Date?,
    val notAfter: Date?,
    val claimedTime: String?,
    val cmsSigningTime: Date?,
    val verifiedTimestamp: Date?,
    val timestampNote: String?,
    val digestAlg: String?,
    val sigAlg: String?,
    val byteRange: List<Long>,
    val byteRangeProblems: List<String>,
    val signedBytes: Long,
    val signedRevision: Int,
    val bytesAfterSignature: Long,
    val laterRevisions: Int,
    val crypto: CryptoStatus,
    val cryptoDetail: String,
    val trustAtSigning: TrustResult?,
    val trustNow: TrustResult?,
    val revocation: RevocationResult?,
    val docMdp: Int?,
    val appName: String?,
    val reason: String?,
    val location: String?,
    val contact: String?,
    val laterChanges: List<LaterChange>,
)

class SignatureResultSet(val signatures: List<SignatureResult>, val findings: List<Finding>, val anchorsDescription: String)

/**
 * Verifies PDF digital signatures from the file's own bytes with BouncyCastle (provider instance passed explicitly,
 * so the platform's cut-down "BC" is never used) and relates what happened after signing to the revision history.
 *
 * Reported separately, on purpose:
 *   1. cryptographic validity (do the signed bytes still match the signature?),
 *   2. certificate trust (does the signer's certificate chain to a root in the supplied trust set?),
 *   3. what was appended after signing, and whether the signature's own terms (DocMDP) allow it,
 *   4. that none of this shows the signed content to be TRUE.
 */
object SignatureAnalyzer {

    private val DIGESTS = mapOf(
        "1.3.14.3.2.26" to "SHA-1", "2.16.840.1.101.3.4.2.4" to "SHA-224", "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384", "2.16.840.1.101.3.4.2.3" to "SHA-512", "1.2.840.113549.2.5" to "MD5",
    )
    private val ENC = mapOf(
        "1.2.840.113549.1.1.1" to "RSA", "1.2.840.113549.1.1.11" to "RSA-SHA256", "1.2.840.113549.1.1.12" to "RSA-SHA384", "1.2.840.113549.1.1.13" to "RSA-SHA512",
        "1.2.840.113549.1.1.5" to "RSA-SHA1", "1.2.840.113549.1.1.10" to "RSA-PSS", "1.2.840.10045.2.1" to "ECDSA", "1.2.840.10045.4.3.2" to "ECDSA-SHA256",
        "1.2.840.10045.4.3.3" to "ECDSA-SHA384", "1.2.840.10045.4.3.4" to "ECDSA-SHA512", "1.3.101.112" to "Ed25519",
    )
    @Suppress("UNCHECKED_CAST")
    private fun sel(id: org.bouncycastle.cms.SignerId): org.bouncycastle.util.Selector<X509CertificateHolder> = id as org.bouncycastle.util.Selector<X509CertificateHolder>

    private val ARCHIVAL_OID = ASN1ObjectIdentifier("1.2.840.113583.1.1.8")

    private const val CAUTION_VALID_NOT_TRUE =
        "A valid signature says nothing about whether the signed information is TRUE: a document created with false information and then signed still verifies."

    fun analyze(file: PdfFile, revisions: List<RevisionInfo>, anchors: List<X509Certificate>, anchorsDescription: String, now: Instant): SignatureResultSet {
        if (file.encrypted) {
            return SignatureResultSet(emptyList(), listOf(
                Finding("SIG_ENCRYPTED", Area.SIGNATURE, EvidenceClass.LIMITATION, "Signatures not examined (encrypted file)",
                    "The document is encrypted.", "Signature dictionaries could not be read reliably.", "Whether the file carries signatures and whether they verify."),
            ), anchorsDescription)
        }
        val found = findSignatureObjects(file)
        if (found.isEmpty()) {
            return SignatureResultSet(emptyList(), listOf(
                Finding("SIG_NONE", Area.SIGNATURE, EvidenceClass.INFO, "No digital signatures",
                    "The file contains no signature dictionaries.",
                    "There is no cryptographic evidence to check the file's integrity against.",
                    "Absence of a signature says nothing about authenticity. An unsigned document can be genuine and a signed one can be false."),
            ), anchorsDescription)
        }
        val fields = fieldNames(file)
        val out = ArrayList<SignatureResult>()
        for ((i, f) in found.withIndex()) out.add(examine(file, revisions, f, i, fields[f.num], anchors, now))
        return SignatureResultSet(out, out.flatMap { findingsFor(it, anchors.isNotEmpty(), anchorsDescription) }, anchorsDescription)
    }

    // ------------------------------------------------------------------------------------------------------------

    private class Found(val num: Int, val dict: PdfDict, val offset: Int, val rev: Int)

    private fun findSignatureObjects(file: PdfFile): List<Found> {
        val seen = HashSet<Int>()
        val out = ArrayList<Found>()
        for (r in file.revisions) for (s in r.sections) for ((num, e) in s.entries) {
            if (e.type != XrefEntryType.IN_USE || !seen.add(num)) continue
            val ind = file.indirectAt(e.a.toInt()) ?: continue
            val d = ind.value as? PdfDict ?: continue
            if (d.has("ByteRange") && d.has("Contents") && (d.name("Type") == null || d.name("Type") == "Sig" || d.name("Type") == "DocTimeStamp")) {
                out.add(Found(num, d, e.a.toInt(), r.index))
            }
        }
        return out.sortedBy { f -> (f.dict.array("ByteRange")?.items?.mapNotNull { (it as? com.docintegrity.forensics.pdf.raw.PdfInt)?.value }?.let { it.getOrNull(2) ?: 0L } ?: 0L) }
    }

    private fun fieldNames(file: PdfFile): Map<Int, String> {
        val out = HashMap<Int, String>()
        val cat = file.resolve(file.trailerValue("Root")) as? PdfDict ?: return out
        val acro = file.resolve(cat["AcroForm"]) as? PdfDict ?: return out
        fun walk(o: com.docintegrity.forensics.pdf.raw.PdfObj, prefix: String, depth: Int) {
            if (depth > 12) return
            val d = file.resolve(o) as? PdfDict ?: return
            val t = (d["T"] as? PdfString)?.text()
            val name = if (t != null) (if (prefix.isEmpty()) t else "$prefix.$t") else prefix
            (d["V"] as? PdfRef)?.let { out[it.num] = name }
            (file.resolve(d["Kids"]) as? PdfArray)?.items?.forEach { walk(it, name, depth + 1) }
        }
        (file.resolve(acro["Fields"]) as? PdfArray)?.items?.forEach { walk(it, "", 0) }
        return out
    }

    private fun docMdpOf(file: PdfFile, f: Found): Int? {
        val refs = file.resolve(f.dict["Reference"]) as? PdfArray
        refs?.items?.forEach { r ->
            val d = file.resolve(r) as? PdfDict ?: return@forEach
            if (d.name("TransformMethod") == "DocMDP") {
                val p = (file.resolve(d["TransformParams"]) as? PdfDict)?.int("P")?.toInt()
                return p ?: 2
            }
        }
        val cat = file.resolve(file.trailerValue("Root")) as? PdfDict
        val perms = file.resolve(cat?.get("Perms")) as? PdfDict
        if ((perms?.get("DocMDP") as? PdfRef)?.num == f.num) return 2
        return null
    }

    private fun examine(file: PdfFile, revisions: List<RevisionInfo>, f: Found, index: Int, field: String?, anchors: List<X509Certificate>, now: Instant): SignatureResult {
        val d = f.dict
        val subFilter = d.name("SubFilter")
        val br = (d.array("ByteRange")?.items?.mapNotNull { (it as? com.docintegrity.forensics.pdf.raw.PdfInt)?.value } ?: emptyList())
        val problems = ArrayList<String>()
        val bytes = file.bytes
        val size = bytes.size.toLong()

        // ---- locate the /Contents value in the file bytes (for the gap check) -----------------------------------------
        val ind = file.indirectAt(f.offset)
        var cStart = -1; var cEnd = -1
        if (ind != null) {
            val lx = PdfLexer(bytes)
            val k = lx.indexOf("/Contents", ind.startOffset, ind.endOffset)
            if (k >= 0) {
                var p = k + 9
                while (p < ind.endOffset && PdfLexer.isWhite(bytes[p].toInt() and 0xFF)) p++
                if (p < ind.endOffset && bytes[p].toInt() == '<'.code && bytes[p + 1].toInt() != '<'.code) {
                    cStart = p
                    var q = p + 1
                    while (q < ind.endOffset && bytes[q].toInt() != '>'.code) q++
                    cEnd = q + 1
                }
            }
        }

        // ---- ByteRange checks --------------------------------------------------------------------------------------------
        var rangesOk = br.size >= 4 && br.size % 2 == 0
        if (!rangesOk) problems.add("ByteRange is not a list of offset/length pairs")
        if (rangesOk) {
            if (br[0] != 0L) problems.add("the signed range does not start at byte 0 (starts at ${br[0]})")
            var prevEnd = -1L
            for (i in br.indices step 2) {
                val a = br[i]; val l = br[i + 1]
                if (a < 0 || l < 0 || a + l > size) { problems.add("a signed range ends beyond the file (bytes $a–${a + l} of $size)"); rangesOk = false }
                if (a < prevEnd) { problems.add("signed ranges overlap or are out of order"); rangesOk = false }
                prevEnd = a + l
            }
        }
        if (rangesOk && br.size == 4) {
            if (cStart < 0) problems.add("the /Contents value could not be located in the file bytes")
            else if (br[0] + br[1] != cStart.toLong() || br[2] != cEnd.toLong()) {
                problems.add("the gap between the signed ranges (bytes ${br[0] + br[1]}–${br[2]}) is not exactly the signature value (bytes $cStart–$cEnd): content could be hidden in the unsigned gap")
            }
        } else if (rangesOk && br.size > 4) problems.add("ByteRange has ${br.size / 2} ranges; only two are normal")
        val end = if (br.size >= 4) br[br.size - 2] + br[br.size - 1] else 0L
        val sigRev = f.rev
        val revEnd = file.revisions.getOrNull(sigRev)?.prefixEnd?.toLong() ?: size
        if (rangesOk && revEnd - end > 2) problems.add("the signature does not cover the last ${revEnd - end} bytes of the revision it was applied in")
        val signedLen = if (rangesOk) (br.indices step 2).sumOf { br[it + 1] } else 0L
        val after = if (rangesOk) size - end else 0L
        val later = file.lastRevision - sigRev

        // ---- cryptographic verification ----------------------------------------------------------------------------------
        var crypto = CryptoStatus.MALFORMED; var detail = "no usable signature value"
        var signerCert: X509Certificate? = null
        var embedded = emptyList<X509Certificate>()
        var digestAlg: String? = null; var sigAlg: String? = null
        var cmsTime: Date? = null; var tsTime: Date? = null; var tsNote: String? = null
        var crls = emptyList<ByteArray>(); var ocsps = emptyList<ByteArray>()
        val timestampOnly = subFilter == "ETSI.RFC3161" || d.name("Type") == "DocTimeStamp"
        val contents = (d["Contents"] as? PdfString)?.bytes
        if (contents != null && rangesOk && contents.isNotEmpty()) {
            val signedBytes = java.io.ByteArrayOutputStream()
            for (i in br.indices step 2) signedBytes.write(bytes, br[i].toInt(), br[i + 1].toInt())
            val sb = signedBytes.toByteArray()
            try {
                val ci = ContentInfo.getInstance(ASN1InputStream(contents).readObject())
                when {
                    timestampOnly -> {
                        val tst = TimeStampToken(CMSSignedData(ci))
                        val imprintAlg = tst.timeStampInfo.toASN1Structure().messageImprint.hashAlgorithm.algorithm.id
                        val jca = DIGESTS[imprintAlg]
                        digestAlg = jca
                        val calc = jca?.let { MessageDigest.getInstance(it).digest(sb) }
                        tsTime = tst.timeStampInfo.genTime
                        val cert = tst.certificates.getMatches(sel(tst.sid)).firstOrNull()
                        embedded = tst.certificates.getMatches(null).map { CertTrust.toX509(it as X509CertificateHolder) }
                        if (calc == null) { crypto = CryptoStatus.UNSUPPORTED; detail = "unsupported timestamp imprint algorithm $imprintAlg" }
                        else if (!calc.contentEquals(tst.timeStampInfo.messageImprintDigest)) { crypto = CryptoStatus.DIGEST_MISMATCH; detail = "the timestamp's message imprint does not match the covered bytes" }
                        else if (cert == null) { crypto = CryptoStatus.UNSUPPORTED; detail = "timestamp authority certificate is not embedded" }
                        else {
                            tst.validate(JcaSimpleSignerInfoVerifierBuilder().setProvider(CertTrust.bc).build(cert as X509CertificateHolder))
                            crypto = CryptoStatus.VALID; detail = "document timestamp verified; asserts the covered bytes existed at ${tsTime}"
                            signerCert = CertTrust.toX509(cert)
                        }
                    }
                    subFilter == "adbe.pkcs7.detached" || subFilter == "ETSI.CAdES.detached" || subFilter == "adbe.pkcs7.sha1" -> {
                        val sd = if (subFilter == "adbe.pkcs7.sha1") CMSSignedData(ci) else CMSSignedData(CMSProcessableByteArray(sb), ci)
                        embedded = sd.certificates.getMatches(null).map { CertTrust.toX509(it as X509CertificateHolder) }
                        val signers = sd.signerInfos.signers.toList()
                        if (signers.isEmpty()) { crypto = CryptoStatus.MALFORMED; detail = "the signature contains no signer" }
                        else {
                            if (subFilter == "adbe.pkcs7.sha1") {
                                val content = sd.signedContent?.content as? ByteArray
                                if (content == null || !content.contentEquals(MessageDigest.getInstance("SHA-1").digest(sb))) {
                                    crypto = CryptoStatus.DIGEST_MISMATCH; detail = "the SHA-1 digest of the covered bytes differs from the signed digest"
                                }
                            }
                            if (crypto != CryptoStatus.DIGEST_MISMATCH) {
                                val s = signers[0]
                                digestAlg = DIGESTS[s.digestAlgOID] ?: s.digestAlgOID
                                sigAlg = ENC[s.encryptionAlgOID] ?: s.encryptionAlgOID
                                val holder = sd.certificates.getMatches(sel(s.sid)).firstOrNull() as? X509CertificateHolder
                                if (holder == null) { crypto = CryptoStatus.UNSUPPORTED; detail = "the signer's certificate is not embedded in the signature" }
                                else {
                                    signerCert = CertTrust.toX509(holder)
                                    val verdict = verifySigners(signers, sd)
                                    crypto = verdict.first; detail = verdict.second
                                    cmsTime = s.signedAttributes?.get(CMSAttributes.signingTime)?.attrValues?.getObjectAt(0)?.let { Time.getInstance(it).date }
                                    val tsAttr = s.unsignedAttributes?.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)
                                    if (tsAttr != null) {
                                        val r = verifyTimestamp(s, tsAttr.attrValues.getObjectAt(0), anchors)
                                        tsTime = r.first; tsNote = r.second
                                    }
                                    s.signedAttributes?.get(ARCHIVAL_OID)?.attrValues?.getObjectAt(0)?.let {
                                        val (c, o) = CertTrust.parseRevocationArchival(it.toASN1Primitive()); crls = c; ocsps = o
                                    }
                                }
                            }
                        }
                    }
                    else -> { crypto = CryptoStatus.UNSUPPORTED; detail = "signature sub-filter “$subFilter” is not supported (legacy or proprietary)" }
                }
            } catch (e: Exception) {
                crypto = CryptoStatus.MALFORMED; detail = "the signature value could not be parsed (${e.javaClass.simpleName}${e.message?.let { ": " + it.take(80) } ?: ""})"
            }
        } else if (!rangesOk) {
            detail = "the ByteRange is unusable, so the signed bytes cannot be determined"
        }

        // ---- DSS embedded validation data ---------------------------------------------------------------------------------
        val dss = dssData(file)
        val allEmbedded = (embedded + dss.certs).distinctBy { it.encoded.contentHashCode() to it.serialNumber }
        val crlAll = crls + dss.crls; val ocspAll = ocsps + dss.ocsps

        // ---- trust and revocation ----------------------------------------------------------------------------------------------
        val claimed = (d["M"] as? PdfString)?.text()
        val claimedDate = PdfDates.parsePdf(claimed)?.takeIf { it.valid }?.instant()?.toInstant()?.let { Date.from(it) }
        val whenSigned = tsTime ?: cmsTime ?: claimedDate
        var trustAt: TrustResult? = null; var trustNow: TrustResult? = null; var rev: RevocationResult? = null
        if (signerCert != null) {
            trustAt = CertTrust.trust(signerCert, allEmbedded, anchors, whenSigned)
            trustNow = CertTrust.trust(signerCert, allEmbedded, anchors, Date.from(now))
            rev = CertTrust.revocation(signerCert, allEmbedded + anchors, crlAll, ocspAll, whenSigned)
        }

        // ---- what happened after signing ---------------------------------------------------------------------------------------
        val laterChanges = ArrayList<LaterChange>()
        for (r in revisions.drop(sigRev + 1)) for (c in r.changes) {
            if (c.type == ChangeType.REWRITTEN_IDENTICAL) continue
            if (c.kind == ObjectKind.XREF_STREAM || c.kind == ObjectKind.OBJECT_STREAM) continue
            laterChanges.add(LaterChange(r.index, classify(c), "obj ${c.num} ${c.kind.label}${c.page?.let { " (page ${it + 1})" } ?: ""} ${c.type.label}: ${c.summary}"))
        }

        val mdp = docMdpOf(file, f)
        val build = (file.resolve(d["Prop_Build"]) as? PdfDict)?.let { pb -> (file.resolve(pb["App"]) as? PdfDict)?.let { (it["Name"] as? PdfName)?.value } }
        return SignatureResult(
            index = index, objNum = f.num, fieldName = field, subFilter = subFilter, timestampOnly = timestampOnly,
            signerCn = signerCert?.let { CertTrust.subjectCn(it) }, certSubject = signerCert?.subjectX500Principal?.name, certIssuer = signerCert?.issuerX500Principal?.name,
            serialHex = signerCert?.serialNumber?.toString(16), notBefore = signerCert?.notBefore, notAfter = signerCert?.notAfter,
            claimedTime = claimed, cmsSigningTime = cmsTime, verifiedTimestamp = tsTime.takeIf { tsNote != null || timestampOnly }, timestampNote = tsNote,
            digestAlg = digestAlg, sigAlg = sigAlg, byteRange = br, byteRangeProblems = problems, signedBytes = signedLen, signedRevision = sigRev,
            bytesAfterSignature = after, laterRevisions = later, crypto = crypto, cryptoDetail = detail,
            trustAtSigning = trustAt, trustNow = trustNow, revocation = rev, docMdp = mdp, appName = build,
            reason = (d["Reason"] as? PdfString)?.text(), location = (d["Location"] as? PdfString)?.text(), contact = (d["ContactInfo"] as? PdfString)?.text(),
            laterChanges = laterChanges,
        )
    }

    private fun verifySigners(signers: List<SignerInformation>, sd: CMSSignedData): Pair<CryptoStatus, String> {
        for (s in signers) {
            val holder = sd.certificates.getMatches(sel(s.sid)).firstOrNull() as? X509CertificateHolder
                ?: return CryptoStatus.UNSUPPORTED to "a signer's certificate is not embedded"
            try {
                // Verify with the bare public key: BouncyCastle would otherwise refuse certificates that had expired at the claimed
                // signing time, mixing certificate validity into cryptographic validity. Certificate validity is judged in the trust step.
                val ok = s.verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(CertTrust.bc).build(CertTrust.toX509(holder).publicKey))
                if (!ok) return CryptoStatus.SIGNATURE_INVALID to "the signature value does not verify with the signer's public key"
            } catch (e: CMSSignerDigestMismatchException) {
                return CryptoStatus.DIGEST_MISMATCH to "the digest of the signed bytes differs from the digest the signer signed (message-digest attribute)"
            } catch (e: CMSException) {
                return CryptoStatus.SIGNATURE_INVALID to "verification failed (${e.message?.take(100)})"
            } catch (e: Exception) {
                return CryptoStatus.UNSUPPORTED to "this signature algorithm could not be processed (${e.javaClass.simpleName})"
            }
        }
        return CryptoStatus.VALID to "the signature value verifies and the digest of the signed bytes matches"
    }

    private fun verifyTimestamp(signer: SignerInformation, value: org.bouncycastle.asn1.ASN1Encodable, anchors: List<X509Certificate>): Pair<Date?, String> {
        return try {
            val tst = TimeStampToken(CMSSignedData(ContentInfo.getInstance(value)))
            val alg = tst.timeStampInfo.toASN1Structure().messageImprint.hashAlgorithm.algorithm.id
            val jca = DIGESTS[alg] ?: return null to "timestamp present but uses an unsupported imprint algorithm"
            val expected = MessageDigest.getInstance(jca).digest(signer.signature)
            if (!expected.contentEquals(tst.timeStampInfo.messageImprintDigest)) return null to "timestamp present but its imprint does not match this signature"
            val cert = tst.certificates.getMatches(sel(tst.sid)).firstOrNull() as? X509CertificateHolder ?: return null to "timestamp present but the TSA certificate is not embedded"
            tst.validate(JcaSimpleSignerInfoVerifierBuilder().setProvider(CertTrust.bc).build(cert))
            val tsa = CertTrust.toX509(cert)
            val emb = tst.certificates.getMatches(null).map { CertTrust.toX509(it as X509CertificateHolder) }
            val tr = CertTrust.trust(tsa, emb, anchors, tst.timeStampInfo.genTime)
            tst.timeStampInfo.genTime to "RFC 3161 timestamp verified: the signature existed at ${tst.timeStampInfo.genTime}. Timestamp authority “${CertTrust.subjectCn(tsa)}”: ${tr.status.label}"
        } catch (e: Exception) { null to "timestamp present but could not be verified (${e.javaClass.simpleName})" }
    }

    private class Dss(val certs: List<X509Certificate>, val crls: List<ByteArray>, val ocsps: List<ByteArray>)

    private fun dssData(file: PdfFile): Dss {
        val cat = file.resolve(file.trailerValue("Root")) as? PdfDict
        val dss = file.resolve(cat?.get("DSS")) as? PdfDict ?: return Dss(emptyList(), emptyList(), emptyList())
        fun streams(key: String): List<ByteArray> = (file.resolve(dss[key]) as? PdfArray)?.items?.mapNotNull { (file.resolve(it) as? PdfStream)?.let { s -> StreamDecoder.decode(s).bytes } } ?: emptyList()
        val certs = streams("Certs").mapNotNull { try { CertTrust.toX509(X509CertificateHolder(it)) } catch (e: Exception) { null } }
        return Dss(certs, streams("CRLs"), streams("OCSPs"))
    }

    // ---- classification of changes after signing ----------------------------------------------------------------------------

    private fun classify(c: com.docintegrity.forensics.pdf.analysis.ObjectChange): PostSignChange = when (c.kind) {
        ObjectKind.SIGNATURE -> PostSignChange.SIGNATURE_OR_LTV
        ObjectKind.FORM_FIELD -> if (c.summary.contains("/FT") || c.summary.contains("Sig")) PostSignChange.SIGNATURE_OR_LTV else PostSignChange.FORM_FILL
        ObjectKind.ANNOTATION -> if (c.annotSubtype in RevisionInfo.OVERLAY_ANNOTS) PostSignChange.ANNOTATION_OVERLAY else PostSignChange.ANNOTATION
        ObjectKind.CONTENT_STREAM, ObjectKind.PAGE_TREE -> PostSignChange.VISIBLE_CONTENT
        // A NEW font/image/form XObject is only a resource: it shows nothing until a changed content stream, page or
        // annotation uses it, and those changes are classified on their own. REPLACING an existing one alters what
        // already-signed content displays.
        ObjectKind.IMAGE, ObjectKind.FONT, ObjectKind.FONT_DESCRIPTOR, ObjectKind.FONT_FILE, ObjectKind.FORM_XOBJECT ->
            if (c.type == ChangeType.NEW) PostSignChange.SUPPORTING_RESOURCE else PostSignChange.VISIBLE_CONTENT
        ObjectKind.ACROFORM -> if (keysChanged(c.summary).all { it in setOf("Fields", "SigFlags", "NeedAppearances", "DA", "DR", "Q") }) PostSignChange.FORM_FILL else PostSignChange.OTHER
        ObjectKind.PAGE -> when {
            c.type == ChangeType.NEW || c.type == ChangeType.FREED -> PostSignChange.VISIBLE_CONTENT
            keysChanged(c.summary).all { it in setOf("Annots", "Resources", "StructParents", "Group") } && keysChanged(c.summary).contains("Annots") && !keysChanged(c.summary).contains("Resources") -> PostSignChange.ANNOTATION
            keysChanged(c.summary).all { it == "Annots" } -> PostSignChange.ANNOTATION
            else -> PostSignChange.VISIBLE_CONTENT
        }
        ObjectKind.CATALOG -> if (keysChanged(c.summary).isNotEmpty() && keysChanged(c.summary).all { it in setOf("DSS", "AcroForm", "Extensions", "Perms", "Names", "Metadata") }) PostSignChange.SIGNATURE_OR_LTV else PostSignChange.OTHER
        ObjectKind.INFO, ObjectKind.XMP -> PostSignChange.METADATA
        ObjectKind.STRUCTURE_TAG -> PostSignChange.OTHER
        else -> if (c.summary.contains("/DSS") || c.summary.contains("/VRI") || c.summary.contains("/Cert")) PostSignChange.SIGNATURE_OR_LTV else PostSignChange.OTHER
    }

    private fun keysChanged(summary: String): List<String> =
        Regex("changed keys ([^;]*)").find(summary)?.groupValues?.get(1)?.split(" ")?.filter { it.startsWith("/") }?.map { it.removePrefix("/") } ?: emptyList()

    // ---- findings ---------------------------------------------------------------------------------------------------------------

    private fun fmt(d: Date?) = d?.toInstant()?.toString() ?: "unknown"

    private fun findingsFor(s: SignatureResult, haveAnchors: Boolean, anchorsDescription: String): List<Finding> {
        val out = ArrayList<Finding>()
        val who = s.signerCn?.let { "“$it”" } ?: "unknown signer"
        val label = (if (s.timestampOnly) "Document timestamp" else "Signature") + (s.fieldName?.let { " “$it”" } ?: " ${s.index + 1}")
        val rangesSane = s.byteRangeProblems.isEmpty()
        val cryptoValid = s.crypto == CryptoStatus.VALID && rangesSane
        val details = buildList {
            add("Signer" to who); s.certIssuer?.let { add("Issuer" to it) }; s.serialHex?.let { add("Serial" to it) }
            if (s.notBefore != null) add("Certificate valid" to "${fmt(s.notBefore)} → ${fmt(s.notAfter)}")
            add("Sub-filter" to (s.subFilter ?: "?")); s.digestAlg?.let { add("Digest" to it) }; s.sigAlg?.let { add("Algorithm" to it) }
            add("Signed bytes" to "${s.signedBytes} of the first ${s.byteRange.takeLast(2).sum()} bytes; ByteRange ${s.byteRange}")
            s.claimedTime?.let { add("Claimed signing time (/M)" to it) }; s.cmsSigningTime?.let { add("Signing time in signature" to fmt(it)) }
            s.timestampNote?.let { add("Timestamp" to it) }
            s.reason?.let { add("Reason" to it) }; s.location?.let { add("Location" to it) }; s.appName?.let { add("Signing software (self-reported)" to it) }
            s.docMdp?.let { add("Certification (DocMDP)" to "level $it: " + when (it) { 1 -> "no changes allowed"; 2 -> "form filling and signing allowed"; else -> "form filling, signing and annotations allowed" }) }
            s.trustAtSigning?.let { add("Certificate trust at signing time" to "${it.status.label} — ${it.detail}") }
            s.trustNow?.let { if (it.status != s.trustAtSigning?.status) add("Certificate trust today" to "${it.status.label} — ${it.detail}") }
            s.revocation?.let { add("Revocation" to "${it.status.label} — ${it.detail}") }
        }

        // 1. cryptographic status -------------------------------------------------------------------------------------------------
        when (s.crypto) {
            CryptoStatus.VALID -> if (!rangesSane) {
                out.add(
                    Finding(
                        id = "SIG_BYTERANGE_ANOMALY", area = Area.SIGNATURE, evidence = EvidenceClass.INDICATOR,
                        title = "$label: signed range is irregular",
                        detected = s.byteRangeProblems.joinToString("; ") + ".",
                        establishes = "The signature verifies over the bytes it declares, but the declared range is not the one a normal signing produces.",
                        unknown = "Irregular ranges are used to attach content the signature does not cover. A valid result over such a range cannot be relied on to protect the whole document.",
                        details = details,
                    ),
                )
            } else if (s.timestampOnly) {
                out.add(
                    Finding(
                        id = "SIG_TIMESTAMP_VALID", area = Area.SIGNATURE, evidence = EvidenceClass.INFO,
                        title = "$label verifies",
                        detected = s.cryptoDetail + ". " + (s.trustAtSigning?.let { "Timestamp authority: ${it.status.label}." } ?: ""),
                        establishes = "A timestamp authority attested that the covered bytes existed at ${fmt(s.verifiedTimestamp)} (if the authority is trusted).",
                        unknown = "A timestamp proves when bytes existed, not that their content is true.",
                        details = details,
                    ),
                )
            } else if (s.laterRevisions == 0 && s.bytesAfterSignature <= 2) {
                out.add(
                    Finding(
                        id = "SIG_VALID_UNMODIFIED", area = Area.SIGNATURE, evidence = EvidenceClass.INFO,
                        title = "$label by $who is cryptographically valid",
                        detected = s.cryptoDetail + "; nothing follows the signed bytes. Certificate: ${s.trustAtSigning?.status?.label ?: "not evaluated"}. Revocation: ${s.revocation?.status?.label ?: "not evaluated"}.",
                        establishes = "The covered bytes are exactly the bytes that the holder of this certificate's private key signed. Nothing in them has changed since signing.",
                        unknown = "$CAUTION_VALID_NOT_TRUE The signer's identity is only as trustworthy as the certificate's chain (${trustSentence(s, haveAnchors, anchorsDescription)}). The signing time is the signer's own claim unless a verified timestamp is shown.",
                        details = details,
                    ),
                )
            } else {
                out.add(
                    Finding(
                        id = "SIG_VALID_EARLIER_REVISION", area = Area.SIGNATURE, evidence = EvidenceClass.INFO,
                        title = "$label by $who is valid for an earlier revision of the file",
                        detected = s.cryptoDetail + "; ${s.bytesAfterSignature} byte(s) in ${s.laterRevisions} later revision(s) follow the signed bytes. Certificate: ${s.trustAtSigning?.status?.label ?: "not evaluated"}.",
                        establishes = "The covered bytes (the file as it was at revision ${s.signedRevision}) are exactly what the holder of this certificate's private key signed. That earlier version can be reconstructed and compared.",
                        unknown = "$CAUTION_VALID_NOT_TRUE What the later revisions changed is assessed in a separate finding. Identity trust: ${trustSentence(s, haveAnchors, anchorsDescription)}.",
                        details = details,
                    ),
                )
            }
            CryptoStatus.DIGEST_MISMATCH -> out.add(
                Finding(
                    id = "SIG_DIGEST_MISMATCH", area = Area.SIGNATURE, evidence = EvidenceClass.ESTABLISHED,
                    title = "$label: the signed content has been changed since signing",
                    detected = s.cryptoDetail + ". Covered: ${s.signedBytes} bytes.",
                    establishes = "The bytes now covered by this signature are not the bytes that were signed. This is cryptographic evidence that the file was modified inside the signed range after $who signed it.",
                    unknown = "It does not say what changed or who changed it. Accidental corruption (a damaged transfer, line-ending conversion, re-encoding) breaks a signature in the same way as deliberate tampering. A re-save by a viewer that does not append incrementally also produces it.",
                    details = details,
                ),
            )
            CryptoStatus.SIGNATURE_INVALID -> out.add(
                Finding(
                    id = "SIG_INVALID", area = Area.SIGNATURE, evidence = EvidenceClass.INDICATOR,
                    title = "$label does not verify",
                    detected = s.cryptoDetail + ".",
                    establishes = "The signature value is not valid for the signer's public key and the signed attributes.",
                    unknown = "A damaged signature, an unsupported variant and a forged signature value all look like this. Whether the document content changed cannot be told from this result.",
                    details = details,
                ),
            )
            CryptoStatus.UNSUPPORTED, CryptoStatus.MALFORMED -> out.add(
                Finding(
                    id = "SIG_UNVERIFIED", area = Area.SIGNATURE, evidence = EvidenceClass.LIMITATION,
                    title = "$label could not be verified",
                    detected = s.cryptoDetail + ".",
                    establishes = "A signature is present, but this tool could not check it.",
                    unknown = "Whether the signed bytes are intact. Use a dedicated validator for this signature type. Absence of a verified signature gives no assurance.",
                    details = details,
                ),
            )
        }
        if (s.crypto == CryptoStatus.MALFORMED || s.crypto == CryptoStatus.UNSUPPORTED) { /* already reported */ }

        // 2. certificate evidence ------------------------------------------------------------------------------------------------
        val tr = s.trustAtSigning
        if (tr != null && !s.timestampOnly) {
            when (tr.status) {
                TrustStatus.EXPIRED_AT_SIGNING -> out.add(
                    Finding(
                        id = "SIG_CERT_NOT_VALID_AT_SIGNING", area = Area.SIGNATURE, evidence = EvidenceClass.INDICATOR,
                        title = "$label: certificate was not valid at the signing time",
                        detected = tr.detail + (if (s.verifiedTimestamp == null) ". The signing time used is the signer's own claim (no verified timestamp)." else "."),
                        establishes = "Judged by the signing time stated in the file, the signer's certificate was outside its validity period.",
                        unknown = "Without a verified timestamp the signing time is unauthenticated: it may be wrong, back-dated or simply the device clock. This does not by itself show the content changed.",
                        details = details,
                    ),
                )
                else -> out.add(
                    Finding(
                        id = "SIG_TRUST", area = Area.SIGNATURE, evidence = if (tr.status == TrustStatus.NOT_EVALUATED) EvidenceClass.LIMITATION else EvidenceClass.INFO,
                        title = "$label: certificate trust — ${tr.status.label}",
                        detected = "${tr.detail}. Chain: ${tr.chain.joinToString(" → ")}. Trust set: ${if (haveAnchors) anchorsDescription else "none supplied"}.",
                        establishes = when (tr.status) {
                            TrustStatus.TRUSTED -> "The signer's certificate chains to a root in the trust set used here."
                            TrustStatus.SELF_SIGNED -> "The certificate is self-signed: it proves only that the same key signed, not who holds it."
                            else -> "The certificate could not be tied to a trusted root with the trust set used here."
                        },
                        unknown = "Trust here means a chain to the listed roots, not that the named person is who they claim to be or that the document is true. Roots used for PDF signing in many countries (Adobe AATL, EU trusted lists) are not part of this device's store, so a legitimate signature can show as untrusted.",
                        details = details,
                    ),
                )
            }
        }
        s.revocation?.let { rv ->
            if (rv.status == RevocationStatus.REVOKED) {
                val before = rv.revokedAt != null && (s.verifiedTimestamp ?: s.cmsSigningTime ?: PdfDates.parsePdf(s.claimedTime)?.instant()?.toInstant()?.let { Date.from(it) })?.let { !rv.revokedAt.after(it) } != false
                out.add(
                    Finding(
                        id = "SIG_REVOKED", area = Area.SIGNATURE, evidence = EvidenceClass.INDICATOR,
                        title = "$label: certificate is revoked per embedded evidence",
                        detected = rv.detail + if (before) ". Revocation is at or before the signing time." else ". Revocation is after the signing time.",
                        establishes = if (before) "The signer's certificate had already been revoked when the signature was made." else "The certificate was revoked later; a signature made before revocation is not invalidated by it.",
                        unknown = "Reasons for revocation (key compromise vs. administrative) are not interpreted here.",
                        details = details,
                    ),
                )
            }
        }

        // 3. changes after signing ------------------------------------------------------------------------------------------------
        if (s.laterChanges.isNotEmpty() && !s.timestampOnly) {
            val byClass = s.laterChanges.groupBy { it.cls }
            val mdp = s.docMdp
            fun forbidden(c: PostSignChange) = when (c) {
                PostSignChange.VISIBLE_CONTENT, PostSignChange.OTHER -> true
                PostSignChange.SUPPORTING_RESOURCE -> false
                PostSignChange.ANNOTATION_OVERLAY, PostSignChange.ANNOTATION -> mdp != null && mdp < 3
                PostSignChange.FORM_FILL -> mdp == 1
                PostSignChange.SIGNATURE_OR_LTV -> mdp == 1 && false
                PostSignChange.METADATA -> mdp == 1
            }
            val serious = byClass.keys.filter { forbidden(it) }
            val reviewOnly = byClass.keys.filter { !forbidden(it) && it == PostSignChange.ANNOTATION_OVERLAY }
            val summary = byClass.entries.joinToString("; ") { (c, l) -> "${l.size} ${c.label} change(s)" }
            val sample = s.laterChanges.take(25).map { "rev ${it.rev}" to it.description } + if (s.laterChanges.size > 25) listOf("…" to "${s.laterChanges.size - 25} more") else emptyList()
            val establishedOk = cryptoValid && serious.isNotEmpty()
            when {
                establishedOk -> out.add(
                    Finding(
                        id = "SIG_CHANGED_AFTER_SIGNING", area = Area.SIGNATURE, evidence = EvidenceClass.ESTABLISHED,
                        title = "$label: the document was changed after it was signed",
                        detected = "After the signed revision, $summary were appended. " + (mdp?.let { "The signature is a certification with DocMDP level $it, which " + (if (it == 1) "allows no changes." else if (it == 2) "allows only form filling and signing." else "allows only form filling, signing and annotations.") } ?: "The signature carries no change restrictions of its own.") +
                            " Changed after signing: " + serious.joinToString { it.label } + ".",
                        establishes = "The signature is cryptographically valid for the earlier revision, which anchors that version as what $who signed. The later revisions contain different content, so the file now differs from the signed version. The signed version can be reconstructed and compared.",
                        unknown = "Whether the later change was legitimate. Some viewers and workflows append content after signing with the signer's consent, and whether the signature's own terms permit a change is a policy question this tool answers only for DocMDP. It does not show who made the change or why.",
                        details = details + sample,
                    ),
                )
                serious.isNotEmpty() -> out.add(
                    Finding(
                        id = "SIG_CHANGED_AFTER_SIGNING_UNANCHORED", area = Area.SIGNATURE, evidence = EvidenceClass.INDICATOR,
                        title = "$label: content follows the signed revision",
                        detected = "After the signed revision, $summary were appended, but this signature could not be verified, so the signed version is not cryptographically anchored.",
                        establishes = "The file contains later revisions that change ${serious.joinToString { it.label }}.",
                        unknown = "Without a valid signature the earlier revision is just part of the same untrusted file.",
                        details = details + sample,
                    ),
                )
                reviewOnly.isNotEmpty() -> out.add(
                    Finding(
                        id = "SIG_OVERLAY_AFTER_SIGNING", area = Area.SIGNATURE, evidence = EvidenceClass.INDICATOR,
                        title = "$label: markup was added after signing",
                        detected = "After the signed revision, $summary were appended.",
                        establishes = "Visible markup (stamp, text box or shape) was added after the signature. The signature remains valid for the earlier revision.",
                        unknown = "The signature's own terms do not forbid annotations, but added markup can change how the page reads. Review it.",
                        details = details + sample,
                    ),
                )
                else -> out.add(
                    Finding(
                        id = "SIG_LATER_BENIGN", area = Area.SIGNATURE, evidence = EvidenceClass.INFO,
                        title = "$label: only permitted additions follow the signature",
                        detected = "After the signed revision, $summary were appended; no page content, image, font or page structure changed.",
                        establishes = "The later revisions are the kind that signing workflows add legitimately (further signatures, validation data, form values, markup) and none altered page content.",
                        unknown = "Whether form values or markup that were added are material. $CAUTION_VALID_NOT_TRUE",
                        details = details + sample,
                    ),
                )
            }
        } else if (s.bytesAfterSignature > 2 && s.laterRevisions == 0 && !s.timestampOnly && rangesSane) {
            out.add(
                Finding(
                    id = "SIG_TRAILING_BYTES", area = Area.SIGNATURE, evidence = EvidenceClass.INDICATOR,
                    title = "$label: bytes follow the signed range that no revision accounts for",
                    detected = "${s.bytesAfterSignature} byte(s) follow the covered range, but no later revision was found.",
                    establishes = "The file is longer than what the signature covers, without a parseable update.",
                    unknown = "A truncated update, a rolled-back revision or appended data. The extra bytes were not interpreted.",
                    details = details,
                ),
            )
        }
        return out
    }

    private fun trustSentence(s: SignatureResult, haveAnchors: Boolean, desc: String) = when {
        s.trustAtSigning == null -> "not evaluated"
        s.trustAtSigning.status == TrustStatus.TRUSTED -> "chains to a root in: $desc"
        !haveAnchors -> "no trust roots were available to this check"
        else -> "${s.trustAtSigning.status.label.lowercase()} for the roots in: $desc"
    }
}
