#!/usr/bin/env python3
"""Generate Matchbox brand PNG assets (recreated from brand brief)."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

CHARCOAL = (0x1A, 0x1A, 0x1A)
CORAL = (0xE8, 0x5D, 0x4C)
CREAM = (0xF5, 0xF0, 0xE6)
WHITE = (0xFF, 0xFF, 0xFF)
TAN = (0xD4, 0xB8, 0x8A)
STRIPE_BROWN = (0x6B, 0x3A, 0x2A)
OUTLINE = (0x0D, 0x0D, 0x0D)

OUT = Path(__file__).resolve().parent.parent / "docs" / "brand"


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _iso_box(
    draw: ImageDraw.ImageDraw,
    origin: tuple[float, float],
    w: float,
    h: float,
    d: float,
    *,
    top_color: tuple[int, int, int],
    front_color: tuple[int, int, int],
    side_color: tuple[int, int, int],
    outline: bool = True,
) -> None:
    ox, oy = origin
    top = [
        (ox, oy),
        (ox + w, oy - w * 0.35),
        (ox + w + d, oy - w * 0.35 + d * 0.35),
        (ox + d, oy + d * 0.35),
    ]
    front = [
        (ox, oy),
        (ox + d, oy + d * 0.35),
        (ox + d, oy + h + d * 0.35),
        (ox, oy + h),
    ]
    side = [
        (ox + w, oy - w * 0.35),
        (ox + w + d, oy - w * 0.35 + d * 0.35),
        (ox + w + d, oy - w * 0.35 + d * 0.35 + h),
        (ox + w, oy - w * 0.35 + h),
    ]
    draw.polygon(top, fill=top_color)
    draw.polygon(front, fill=front_color)
    draw.polygon(side, fill=side_color)
    if outline:
        for poly in (top, front, side):
            draw.polygon(poly, outline=OUTLINE, width=2)


def _honeycomb_strip(
    draw: ImageDraw.ImageDraw,
    rect: tuple[float, float, float, float],
    *,
    cell: float = 10,
    color: tuple[int, int, int] = CREAM,
    bg: tuple[int, int, int] = CHARCOAL,
) -> None:
    x0, y0, x1, y1 = rect
    draw.rectangle(rect, fill=bg)
    row = 0
    y = y0 + cell * 0.5
    while y < y1 - cell * 0.3:
        x = x0 + (cell * 0.5 if row % 2 else cell * 0.2)
        while x < x1 - cell * 0.3:
            draw.ellipse((x, y, x + cell * 0.55, y + cell * 0.55), fill=color)
            x += cell * 0.75
        y += cell * 0.65
        row += 1


def _draw_tray(
    draw: ImageDraw.ImageDraw,
    origin: tuple[float, float],
    w: float,
    h: float,
    d: float,
    slide: float,
) -> None:
    ox, oy = origin
    ox -= slide
    _iso_box(draw, (ox, oy), w * 0.88, h * 0.55, d * 0.88, top_color=CREAM, front_color=CREAM, side_color=(0xE8, 0xE0, 0xD0))
    for i in range(5):
        mx = ox + 18 + i * 14
        my = oy + 8
        draw.line((mx, my, mx + 8, my - 10), fill=TAN, width=3)
        draw.ellipse((mx + 4, my - 18, mx + 14, my - 8), fill=CORAL, outline=OUTLINE, width=1)


def _draw_flame(draw: ImageDraw.ImageDraw, cx: float, cy: float, scale: float = 1.0) -> None:
    s = scale
    outer = [
        (cx, cy - 28 * s),
        (cx + 18 * s, cy - 8 * s),
        (cx + 10 * s, cy + 14 * s),
        (cx - 10 * s, cy + 14 * s),
        (cx - 18 * s, cy - 8 * s),
    ]
    inner = [
        (cx, cy - 16 * s),
        (cx + 7 * s, cy - 2 * s),
        (cx, cy + 8 * s),
        (cx - 7 * s, cy - 2 * s),
    ]
    draw.polygon(outer, fill=CORAL, outline=OUTLINE, width=max(1, int(2 * s)))
    draw.polygon(inner, fill=CREAM)
    for angle in (-40, -10, 20, 50):
        import math

        rad = math.radians(angle)
        x2 = cx + math.cos(rad) * 22 * s
        y2 = cy + math.sin(rad) * 22 * s - 10 * s
        draw.line((cx, cy - 6 * s, x2, y2), fill=CORAL, width=max(1, int(3 * s)))


def _draw_strike_match(draw: ImageDraw.ImageDraw, box_origin: tuple[float, float], box_w: float) -> None:
    ox, oy = box_origin
    x0, y0 = ox + box_w * 0.55, oy - box_w * 0.2
    x1, y1 = ox + box_w * 1.35, oy - box_w * 1.1
    draw.line((x0, y0, x1, y1), fill=TAN, width=6)
    draw.ellipse((x1 - 10, y1 - 10, x1 + 10, y1 + 10), fill=CORAL, outline=OUTLINE, width=2)
    _draw_flame(draw, x0 + 4, y0 - 6, scale=0.9)


def draw_matchbox_mark(
    draw: ImageDraw.ImageDraw,
    origin: tuple[float, float],
    scale: float = 1.0,
    *,
    strike: bool = True,
    flame_on_top: bool = False,
) -> None:
    ox, oy = origin
    w, h, d = 120 * scale, 50 * scale, 36 * scale
    _draw_tray(draw, (ox + 8 * scale, oy + 18 * scale), w, h, d, slide=42 * scale)
    _iso_box(draw, (ox, oy), w, h, d, top_color=CHARCOAL, front_color=CHARCOAL, side_color=(0x2A, 0x2A, 0x2A))
    # strike strip on front-left face
    strip = (ox - 2 * scale, oy + 8 * scale, ox + 34 * scale, oy + h - 2 * scale)
    _honeycomb_strip(draw, strip, cell=7 * scale, color=CORAL, bg=CHARCOAL)
    if flame_on_top:
        _draw_flame(draw, ox + w * 0.45, oy - w * 0.15, scale=0.55 * scale)
    if strike:
        _draw_strike_match(draw, (ox, oy), w)


def make_primary() -> Image.Image:
    img = Image.new("RGBA", (640, 640), WHITE)
    draw = ImageDraw.Draw(img)
    draw_matchbox_mark(draw, (140, 280), scale=1.6, strike=True)
    return img.convert("RGB")


def make_avatar() -> Image.Image:
    img = Image.new("RGBA", (512, 512), CREAM)
    draw = ImageDraw.Draw(img)
    draw_matchbox_mark(draw, (90, 170), scale=1.35, strike=True)
    return img.convert("RGB")


def make_favicon() -> Image.Image:
    img = Image.new("RGBA", (32, 32), CHARCOAL)
    draw = ImageDraw.Draw(img)
    # simplified flame on charcoal
    _draw_flame(draw, 16, 20, scale=0.45)
    draw.rectangle((4, 24, 28, 30), fill=CREAM)
    return img.convert("RGB")


def make_lockup(vertical: bool = False) -> Image.Image:
    if vertical:
        img = Image.new("RGBA", (1200, 630), CREAM)
        mark_origin = (470, 80)
        text_y = 360
        title_x = 600
        anchor = "mm"
    else:
        img = Image.new("RGBA", (1200, 400), CREAM)
        mark_origin = (80, 60)
        text_y = 170
        title_x = 360
        anchor = "lm"

    draw = ImageDraw.Draw(img)
    draw_matchbox_mark(draw, mark_origin, scale=1.2, strike=False, flame_on_top=True)

    title_font = _font(72, bold=True)
    tag_font = _font(28)
    draw.text((title_x, text_y), "Matchbox", fill=CHARCOAL, font=title_font, anchor=anchor)
    draw.text(
        (title_x, text_y + (70 if not vertical else 90)),
        "Disposable cloud servers with a lease.",
        fill=CORAL,
        font=tag_font,
        anchor=anchor,
    )
    return img.convert("RGB")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    make_primary().save(OUT / "primary.png", optimize=True)
    make_avatar().save(OUT / "avatar.png", optimize=True)
    make_favicon().save(OUT / "favicon.png", optimize=True)
    make_lockup(vertical=False).save(OUT / "lockup.png", optimize=True)
    make_lockup(vertical=True).save(OUT / "splash.png", optimize=True)
    print(f"Wrote assets to {OUT}")


if __name__ == "__main__":
    main()
