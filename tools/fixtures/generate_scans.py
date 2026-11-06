#!/usr/bin/env python3
"""
Realistic scan family (paper grain, slight skew, JPEG) and the raster-edit scenarios. Run after generate_fixtures.py.
Usage: python3 generate_scans.py --dir forensics/src/test/resources/fixtures --work /tmp/scanwork

  G0  scan of A, unedited                                   (control)
  G   amount edited as an image: flat patch + typed digits, whole page re-saved at JPEG q92   (double compression)
  Gb  same edit, re-saved at the SAME quality as the scan (q75)                        (hard: no compression trace)
  Gp  amount PASTED from a different scan of the altered document at an unaligned offset      (hard: realistic splice)
  Gs  a separate crisp image (digits) placed over the scan as its own PDF image object
  Gn0 scan whose background was whitened by the scanner software (flat white)           (control, denoised)
  Gn  Gn0 with the amount edited                                                        (hard: patch indistinguishable)
  Gh0 higher-quality grainy scan (JPEG q93, grain sigma 3.4), unedited                   (control for the noise check)
  Gh  Gh0 with the amount edited by a flat patch + typed digits, saved q93                (noise check should see the patch)
  Gx  G0 whose JPEG carries an Exif Software tag of an image editor + Photoshop-style marker
  Gv  G0 with vector text typed over a white patch                                      (see also generate_extra.py)
"""
import argparse, io, os, shutil, subprocess
import fitz, img2pdf, numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

AMT_OLD, AMT_NEW = "4,250.00", "42,500.00"
DPI = 200


def render(pdf, png):
    subprocess.run(["pdftoppm", "-r", str(DPI), "-png", "-singlefile", pdf, png[:-4]], check=True)
    return Image.open(png).convert("RGB")


def scan_of(im, seed, quality, sigma=2.6, angle=0.35, whiten=False):
    a = np.asarray(im).astype(np.float32) * 0.975 + 3.0           # off-white paper
    rng = np.random.default_rng(seed)
    a += rng.normal(0, sigma, a.shape[:2])[..., None]               # luminance grain (paper + sensor)
    a += rng.normal(0, sigma * 0.35, a.shape)                       # a little colour noise
    out = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))
    out = out.filter(ImageFilter.GaussianBlur(0.55)).rotate(angle, resample=Image.BICUBIC, fillcolor=(247, 247, 247))
    if whiten:
        out = out.point(lambda v: 255 if v > 190 else v)
    buf = io.BytesIO(); out.save(buf, "JPEG", quality=quality); buf.seek(0)
    return Image.open(buf).convert("RGB")


def jpg_bytes(im, q):
    b = io.BytesIO(); im.save(b, "JPEG", quality=q); return b.getvalue()


def to_pdf(jpg, pdf):
    with open(pdf, "wb") as f:
        f.write(img2pdf.convert(jpg, layout_fun=img2pdf.get_layout_fun((img2pdf.mm_to_pt(210), img2pdf.mm_to_pt(297)))))


def amount_box(a_pdf):
    r = fitz.open(a_pdf)[0].search_for("ZMW " + AMT_OLD)[0]
    s = DPI / 72
    return (int(r.x0 * s) - 6, int(r.y0 * s) - 4, int(r.x1 * s) + 70, int(r.y1 * s) + 4), r


def flat_edit(im, box, r):
    im = im.copy(); d = ImageDraw.Draw(im)
    fill = tuple(int(v) for v in np.asarray(im).reshape(-1, 3)[:: 997].mean(axis=0))  # paper colour sampled from the page
    d.rectangle(box, fill=fill)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", int((r.y1 - r.y0) * DPI / 72 * 0.85))
    d.text((box[0] + 6, box[1] + 2), "ZMW " + AMT_NEW, fill=(20, 20, 20), font=font)
    return im


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--dir", required=True); ap.add_argument("--work", required=True); a = ap.parse_args()
    d, w = a.dir, a.work; os.makedirs(w, exist_ok=True)
    A = os.path.join(d, "A_original.pdf"); D = os.path.join(d, "D_roundtrip_amount_altered.pdf")
    page = render(A, os.path.join(w, "A.png"))
    box, r = amount_box(A)

    s0 = scan_of(page, seed=11, quality=75)
    to_pdf(jpg_bytes(s0, 75), os.path.join(d, "G0_scan_unedited.pdf"))

    to_pdf(jpg_bytes(flat_edit(s0, box, r), 92), os.path.join(d, "G_scan_amount_edited.pdf"))
    to_pdf(jpg_bytes(flat_edit(s0, box, r), 75), os.path.join(d, "Gb_scan_amount_edited_same_quality.pdf"))

    # Gp: a different physical scan of the ALTERED document; its amount is pasted at an unaligned offset
    altered = render(D, os.path.join(w, "D.png"))
    s1 = scan_of(altered, seed=23, quality=88, angle=0.35)
    pad = 6
    crop_box = (box[0] - pad, box[1] - pad, box[2] + pad, box[3] + pad)
    patch = s1.crop(crop_box)
    sp = s0.copy(); sp.paste(patch, (crop_box[0] + 3, crop_box[1] + 5))
    to_pdf(jpg_bytes(sp, 75), os.path.join(d, "Gp_scan_patch_pasted.pdf"))

    # Gs: separate crisp image object placed over the scan
    to_pdf(jpg_bytes(s0, 75), os.path.join(w, "gs_base.pdf"))
    doc = fitz.open(os.path.join(w, "gs_base.pdf")); pg = doc[0]
    tile = Image.new("RGB", (900, 130), (250, 250, 250)); ImageDraw.Draw(tile).text((10, 20), "ZMW " + AMT_NEW, fill=(20, 20, 20), font=ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 80))
    tb = io.BytesIO(); tile.save(tb, "PNG")
    pg.insert_image(fitz.Rect(r.x0 - 3, r.y0 - 3, r.x0 - 3 + 900 * 0.12, r.y0 - 3 + 130 * 0.12), stream=tb.getvalue())
    doc.save(os.path.join(d, "Gs_scan_image_overlay.pdf"), garbage=3, deflate=True); doc.close()

    # Gn0 / Gn: scanner software whitened the background (flat white everywhere)
    sn = scan_of(page, seed=31, quality=75, whiten=True)
    to_pdf(jpg_bytes(sn, 75), os.path.join(d, "Gn0_scan_whitened_unedited.pdf"))
    to_pdf(jpg_bytes(flat_edit(sn, box, r), 90), os.path.join(d, "Gn_scan_whitened_amount_edited.pdf"))
    # Gh0 / Gh: high-quality grainy scan, so that grain survives compression
    sh = scan_of(page, seed=41, quality=93, sigma=3.4)
    to_pdf(jpg_bytes(sh, 93), os.path.join(d, "Gh0_scan_hq_grainy_unedited.pdf"))
    to_pdf(jpg_bytes(flat_edit(sh, box, r), 93), os.path.join(d, "Gh_scan_hq_grainy_amount_edited.pdf"))

    # Gx: editor traces in the JPEG metadata
    ex = Image.Exif(); ex[0x0131] = "Adobe Photoshop 25.1 (Windows)"; ex[0x0132] = "2025:03:02 14:11:09"
    b = io.BytesIO(); s0.save(b, "JPEG", quality=75, exif=ex.tobytes()); to_pdf(b.getvalue(), os.path.join(d, "Gx_scan_editor_traces.pdf"))
    print("scan fixtures written")


if __name__ == "__main__":
    main()
