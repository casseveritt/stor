"""Watermark pipeline — applied at delivery time, never to stored content.

Only images are watermarked in this implementation. Video (FFmpeg) and
other media types pass through unchanged — they are not "failures".

If watermarking is enabled and the content IS an image but watermarking
fails for any reason, WatermarkError is raised. Callers must return an
error to the client rather than fall back to un-watermarked delivery.
"""
import io

from PIL import Image, ImageDraw, ImageFont

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
]


class WatermarkError(Exception):
    pass


def _load_font(size: int) -> ImageFont.ImageFont:
    for path in _FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _watermark_image(content: bytes, identity: str) -> bytes:
    from PIL import ImageOps
    img = ImageOps.exif_transpose(Image.open(io.BytesIO(content))).convert("RGBA")
    w, h = img.size

    font_size = max(12, min(w, h) // 15)
    font = _load_font(font_size)

    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    bbox = draw.textbbox((0, 0), identity, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    x = max(4, (w - text_w) // 2)
    y = max(4, (h - text_h) // 2)

    draw.text((x + 1, y + 1), identity, font=font, fill=(0, 0, 0, 140))
    draw.text((x, y), identity, font=font, fill=(255, 255, 255, 200))

    result = Image.alpha_composite(img, overlay).convert("RGB")
    buf = io.BytesIO()
    result.save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def apply(content: bytes, media_type: str, recipient_identity: str) -> bytes:
    """Watermark content for the given recipient.

    Images get a visible text overlay. Other types pass through unchanged.
    Raises WatermarkError if image watermarking fails — callers must not
    serve the un-watermarked content in that case.
    """
    if not media_type.startswith("image/"):
        return content
    try:
        return _watermark_image(content, recipient_identity)
    except Exception as exc:
        raise WatermarkError(f"Watermarking failed: {exc}") from exc
