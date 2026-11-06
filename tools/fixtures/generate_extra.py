#!/usr/bin/env python3
"""
Extra overlay scenarios built from the base fixtures (run after generate_fixtures.py):
  Fw  A with the name WHITED OUT (opaque white rectangle painted over it) and a new name typed above it
  Gv  G0 (scan) with a white patch drawn over the amount and new vector text typed over the scan
Usage: python3 generate_extra.py --dir forensics/src/test/resources/fixtures
"""
import argparse, os, shutil
import fitz

NAME_OLD, NAME_NEW = "John Mwansa", "Joseph Mwanza"
AMT_OLD, AMT_NEW = "4,250.00", "42,500.00"

ap = argparse.ArgumentParser(); ap.add_argument("--dir", required=True); a = ap.parse_args()
d = a.dir

# Fw: white-out and retype on a vector PDF (full save so the original text object is still in the stream)
dst = os.path.join(d, "Fw_whiteout_retype.pdf")
shutil.copy(os.path.join(d, "A_original.pdf"), dst)
doc = fitz.open(dst); page = doc[0]
r = page.search_for(NAME_OLD)[0]
page.draw_rect(fitz.Rect(r.x0 - 1, r.y0 - 1, r.x1 + 2, r.y1 + 1), color=None, fill=(1, 1, 1), overlay=True)
page.insert_text((r.x0, r.y1 - 2.2), NAME_NEW, fontname="helv", fontsize=12)
tmp = dst + ".tmp"; doc.save(tmp, garbage=0, deflate=False); doc.close(); os.replace(tmp, dst)

# Gv: vector text typed over a scan (patch + text)
dst = os.path.join(d, "Gv_scan_vector_overlay.pdf")
shutil.copy(os.path.join(d, "G0_scan_unedited.pdf"), dst)
doc = fitz.open(dst); page = doc[0]
ref = fitz.open(os.path.join(d, "A_original.pdf"))[0]
r = ref.search_for("ZMW " + AMT_OLD)[0]            # same page geometry (A4) as the scan
page.draw_rect(fitz.Rect(r.x0 - 3, r.y0 - 2, r.x1 + 24, r.y1 + 2), color=None, fill=(0.98, 0.98, 0.98), overlay=True)
page.insert_text((r.x0, r.y1 - 2.5), "ZMW " + AMT_NEW, fontname="helv", fontsize=12)
tmp = dst + ".tmp"; doc.save(tmp, garbage=0); doc.close(); os.replace(tmp, dst)
print("wrote Fw_whiteout_retype.pdf, Gv_scan_vector_overlay.pdf")
