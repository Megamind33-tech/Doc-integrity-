#!/usr/bin/env python3
"""
Signed-PDF fixtures made with pyHanko (an independent implementation) and a throw-away test CA.
Run after generate_fixtures.py.   Usage: python3 generate_signed.py --dir forensics/src/test/resources/fixtures

  H0  A signed by a CA-issued certificate, nothing changed afterwards
  H1  H0 with one byte flipped INSIDE the signed range (same length)
  H2  H0 followed by an incremental edit of the name (content changed after signing)
  H3  H0 followed by a SECOND signature by another signer (legitimate co-signing)
  H4  A signed with a SELF-SIGNED certificate
  H5  A signed with an embedded RFC 3161 signature timestamp (test TSA)
  H6  A CERTIFIED (DocMDP: no changes allowed) then an annotation is added afterwards
  H7  D (the document with the ALTERED amount) validly signed: valid signature, false content
  H8  A signed with a certificate whose validity period had already ended at signing time
  H9  H0 followed by an RFC 3161 DOCUMENT timestamp (LTV-style append)
  test_root_ca.pem / test_tsa_ca.pem: the throw-away trust anchors (for tests only)
"""
import argparse
import datetime
import io
import os
import shutil

import fitz
from asn1crypto import keys as a_keys, x509 as a_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, timestamps
from pyhanko_certvalidator.registry import SimpleCertificateStore

NOW = datetime.datetime.now(datetime.timezone.utc)


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(cn, o="Doc Forensics Test"):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, o), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, subject_key, issuer, issuer_key, ca=False, days=(-30, 365), eku=None, self_signed=False, usage="sign"):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(subject_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW + datetime.timedelta(days=days[0])).not_valid_after(NOW + datetime.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None if ca else None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    elif usage == "sign":
        b = b.add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def to_asn1(c, k):
    return (a_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER)),
            a_keys.PrivateKeyInfo.load(k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM)


def signer_for(c, k, chain):
    ac, ak = to_asn1(c, k)
    return signers.SimpleSigner(signing_cert=ac, signing_key=ak, cert_registry=SimpleCertificateStore.from_certs([to_asn1(x, k)[0] for x in chain]), signature_mechanism=None)


def sign(src, dst, signer, field="Signature1", certify=False, timestamper=None, reason="Approved", location="Lusaka"):
    with open(src, "rb") as f:
        w = IncrementalPdfFileWriter(f)
        fields.append_signature_field(w, fields.SigFieldSpec(sig_field_name=field))
        meta = signers.PdfSignatureMetadata(
            field_name=field, reason=reason, location=location, md_algorithm="sha256", certify=certify,
            docmdp_permissions=fields.MDPPerm.NO_CHANGES if certify else fields.MDPPerm.FILL_FORMS,
        )
        out = signers.sign_pdf(w, meta, signer=signer, timestamper=timestamper)
        with open(dst, "wb") as o:
            o.write(out.getbuffer())


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--dir", required=True); a = ap.parse_args()
    d = a.dir
    A = os.path.join(d, "A_original.pdf")
    D = os.path.join(d, "D_roundtrip_amount_altered.pdf")

    root_k = key(); root_n = name("Doc Forensics Test Root CA")
    root = cert(root_n, root_k, root_n, root_k, ca=True, days=(-365, 3650), self_signed=True)
    tsa_ca_k = key(); tsa_n = name("Doc Forensics Test TSA")
    tsa_c = cert(tsa_n, tsa_ca_k, root_n, root_k, eku=[ExtendedKeyUsageOID.TIME_STAMPING], usage="tsa")
    grace_k = key(); grace = cert(name("Grace Banda", "Finance Office"), grace_k, root_n, root_k)
    amos_k = key(); amos = cert(name("Amos Phiri", "Registrar"), amos_k, root_n, root_k)
    ss_k = key(); ss_n = name("Self Signer", "Nobody"); selfs = cert(ss_n, ss_k, ss_n, ss_k)
    old_k = key(); old = cert(name("Old Officer", "Finance Office"), old_k, root_n, root_k, days=(-800, -400))

    open(os.path.join(d, "test_root_ca.pem"), "wb").write(pem(root))
    open(os.path.join(d, "test_tsa_cert.pem"), "wb").write(pem(tsa_c))

    s_grace = signer_for(grace, grace_k, [root])
    s_amos = signer_for(amos, amos_k, [root])
    h0 = os.path.join(d, "H0_signed_valid.pdf")
    sign(A, h0, s_grace)

    # H1: flip one byte inside the signed range, keeping length
    b = bytearray(open(h0, "rb").read())
    i = bytes(b).index(b"ReportLab")
    b[i + 8] = ord("c")      # "ReportLab" -> "ReportLac"
    open(os.path.join(d, "H1_signed_bytes_flipped.pdf"), "wb").write(bytes(b))

    # H2: incremental edit after signing (PyMuPDF appends; the signed bytes stay untouched)
    h2 = os.path.join(d, "H2_signed_then_edited.pdf")
    shutil.copy(h0, h2)
    doc = fitz.open(h2); page = doc[0]
    r = page.search_for("John Mwansa")[0]
    page.add_redact_annot(fitz.Rect(r.x0 - 1, r.y0 - 1, r.x1 + 2, r.y1 + 1), fill=(1, 1, 1)); page.apply_redactions()
    page.insert_text((r.x0, r.y1 - 2.7), "Joseph Mwanza", fontname="helv", fontsize=12)
    doc.saveIncr(); doc.close()

    # H3: legitimate second signature after the first
    sign(h0, os.path.join(d, "H3_signed_then_cosigned.pdf"), s_amos, field="Signature2", reason="Countersigned")

    # H4: self-signed
    sign(A, os.path.join(d, "H4_signed_self_signed.pdf"), signer_for(selfs, ss_k, [selfs]))

    # H5: with signature timestamp
    ts = timestamps.DummyTimeStamper(tsa_cert=to_asn1(tsa_c, tsa_ca_k)[0], tsa_key=to_asn1(tsa_c, tsa_ca_k)[1],
                                     certs_to_embed=[to_asn1(root, root_k)[0]], fixed_dt=NOW)
    sign(A, os.path.join(d, "H5_signed_timestamped.pdf"), s_grace, timestamper=ts)

    # H6: certified (no changes allowed), then an annotation is added
    h6 = os.path.join(d, "H6_certified_then_annotated.pdf")
    sign(A, h6, s_grace, certify=True, reason="Certified")
    doc = fitz.open(h6); page = doc[0]
    page.add_freetext_annot(fitz.Rect(300, 60, 520, 90), "PAID IN FULL", fontsize=14, text_color=(1, 0, 0))
    doc.saveIncr(); doc.close()

    # H7: false information, validly signed
    sign(D, os.path.join(d, "H7_signed_false_content.pdf"), s_grace)

    # H8: certificate no longer valid at signing time
    sign(A, os.path.join(d, "H8_signed_cert_expired.pdf"), signer_for(old, old_k, [root]))
    # H9: document timestamp appended to H0
    with open(h0, "rb") as f:
        w = IncrementalPdfFileWriter(f)
        out = signers.PdfTimeStamper(ts).timestamp_pdf(w, md_algorithm="sha256")
        open(os.path.join(d, "H9_signed_then_doc_timestamp.pdf"), "wb").write(out.getbuffer())
    print("signed fixtures written to", d)


if __name__ == "__main__":
    main()
