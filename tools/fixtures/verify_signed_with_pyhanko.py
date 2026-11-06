#!/usr/bin/env python3
"""Independent ground truth: validates the signed fixtures with pyHanko and prints what it concludes."""
import argparse, glob, os
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko.keys import load_cert_from_pemder

ap = argparse.ArgumentParser(); ap.add_argument("--dir", required=True); a = ap.parse_args()
root = load_cert_from_pemder(os.path.join(a.dir, "test_root_ca.pem"))
tsa = load_cert_from_pemder(os.path.join(a.dir, "test_tsa_cert.pem"))
for f in sorted(glob.glob(os.path.join(a.dir, "H*.pdf"))):
    with open(f, "rb") as fh:
        r = PdfFileReader(fh)
        for sig in r.embedded_signatures:
            vc = ValidationContext(trust_roots=[root, tsa], allow_fetching=False, revocation_mode="soft-fail")
            try:
                st = validate_pdf_signature(sig, vc)
                print(f"{os.path.basename(f):38s} {sig.field_name:11s} intact={st.intact!s:5s} valid={st.valid!s:5s} trusted={st.trusted!s:5s} "
                      f"coverage={st.coverage.name:24s} modification={getattr(st.modification_level,'name',None)} docmdp={getattr(st.docmdp_ok,'__str__',lambda:'')()}")
            except Exception as e:
                print(f"{os.path.basename(f):38s} {sig.field_name:11s} EXCEPTION {type(e).__name__}: {str(e)[:100]}")
