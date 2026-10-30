"""Minimal, dependency-free PDF writer for analytical reports.

Produces a standards-compliant single-font PDF using only the standard
Helvetica/Helvetica-Bold font metrics. Content is text-only by design: every
figure in the PDF is copied from the stored report summary.
"""

from __future__ import annotations

from datetime import datetime

from .text import plural

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN = 56
LINE_HEIGHT = 14
MAX_LINES = 46


def _escape(text: str) -> str:
    cleaned = (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )
    return "".join(ch if ord(ch) < 256 else "?" for ch in cleaned)


def _wrap(text: str, width: int = 96) -> list[str]:
    words = str(text).split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            while len(word) > width:
                lines.append(word[:width])
                word = word[width:]
            current = word
    if current:
        lines.append(current)
    return lines or [""]


class _Line:
    __slots__ = ("text", "size", "bold", "gap")

    def __init__(self, text: str, size: int = 10, bold: bool = False, gap: int = 4) -> None:
        self.text = text
        self.size = size
        self.bold = bold
        self.gap = gap


def _stream(lines: list[_Line], page_no: int, pages: int) -> bytes:
    parts: list[str] = []
    y = PAGE_HEIGHT - MARGIN
    for line in lines:
        y -= line.size + line.gap
        if y < MARGIN + 20:
            break
        font = "/F2" if line.bold else "/F1"
        parts.append(
            f"BT {font} {line.size} Tf {MARGIN} {y:.1f} Td ({_escape(line.text)}) Tj ET"
        )
    parts.append(
        f"BT /F1 8 Tf {MARGIN} 30 Td (SENTINEL AI  |  generated {datetime.utcnow():%Y-%m-%d %H:%M}Z  |  page {page_no} of {pages}) Tj ET"
    )
    body = "\n".join(parts)
    return body.encode("latin-1", errors="replace")


def render_report_pdf(summary: dict) -> bytes:
    lines: list[_Line] = []
    lines.append(_Line("SENTINEL AI", 18, True, 2))
    lines.append(_Line("Passive network threat intelligence report", 11, False, 10))
    lines.append(_Line(f"Workspace: {summary['workspace']['name']} ({summary['workspace']['slug']})", 10))
    lines.append(_Line(f"Environment: {summary['environment']}   Period: {summary['period']['label']}", 10))
    lines.append(_Line(f"Range: {summary['period']['start']}  to  {summary['period']['end']}", 9))
    lines.append(_Line(f"Generated: {summary['generated_at']}", 9, gap=12))

    lines.append(_Line("1. Summary", 13, True, 6))
    for key, value in summary["totals"].items():
        lines.append(_Line(f"{key.replace('_', ' ').title()}: {value:,}" if isinstance(value, int) else f"{key.replace('_', ' ').title()}: {value}", 10, gap=2))

    lines.append(_Line("2. Severity distribution", 13, True, 8))
    for item in summary["severity_distribution"]:
        lines.append(_Line(f"{item['severity'].title()}: {item['count']}", 10, gap=2))

    lines.append(_Line("3. Threat categories", 13, True, 8))
    if summary["category_distribution"]:
        for item in summary["category_distribution"]:
            lines.append(_Line(f"{item['category'].replace('_', ' ')}: {item['count']}", 10, gap=2))
    else:
        lines.append(_Line("No alerts were generated in the selected period.", 10, gap=2))

    lines.append(_Line("4. Detector outcomes", 13, True, 8))
    if summary["detector_performance"]:
        for item in summary["detector_performance"]:
            confidence = item.get("avg_confidence")
            lines.append(
                _Line(
                    f"{item['name']}: {item['alerts']} {plural(item['alerts'], 'alert')}; mean score "
                    f"{confidence if confidence is not None else 'n/a'}; "
                    f"false positives {item['false_positives']}",
                    9,
                    gap=2,
                )
            )
    else:
        lines.append(_Line("No detector outcomes recorded in this period.", 10, gap=2))

    lines.append(_Line("5. Protocol mix", 13, True, 8))
    if summary["protocol_distribution"]:
        for item in summary["protocol_distribution"][:8]:
            lines.append(_Line(f"{item['protocol']}: {item['count']} {plural(item['count'], 'flow')}", 10, gap=2))
    else:
        lines.append(_Line("No protocol metadata observed.", 10, gap=2))

    lines.append(_Line("6. Processing", 13, True, 8))
    for key, value in summary["processing"].items():
        if key == "note":
            continue
        lines.append(_Line(f"{key.replace('_', ' ').title()}: {value}", 10, gap=2))

    lines.append(_Line("7. Data linkage and limitations", 13, True, 8))
    lines.append(_Line(summary["query"]["description"], 9, gap=3))
    for limitation in summary["limitations"]:
        for wrapped in _wrap(limitation, 100):
            lines.append(_Line(wrapped, 9, gap=1))

    pages: list[list[_Line]] = []
    cursor: list[_Line] = []
    remaining = MAX_LINES
    for line in lines:
        if remaining <= 0:
            pages.append(cursor)
            cursor = []
            remaining = MAX_LINES
        cursor.append(line)
        remaining -= 1
    if cursor:
        pages.append(cursor)

    total_pages = len(pages)
    font_regular_id = 3
    font_bold_id = 4
    first_page_id = 5
    page_ids = [first_page_id + 2 * i for i in range(total_pages)]
    content_ids = [first_page_id + 2 * i + 1 for i in range(total_pages)]

    objects: dict[int, bytes] = {}
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {total_pages} >>".encode()
    objects[font_regular_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    objects[font_bold_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"

    for index, page_lines in enumerate(pages):
        content = _stream(page_lines, index + 1, total_pages)
        page_id = page_ids[index]
        content_id = content_ids[index]
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {font_regular_id} 0 R /F2 {font_bold_id} 0 R >> >> "
            f"/Contents {content_id} 0 R >>"
        ).encode()
        objects[content_id] = (
            f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream"
        )

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for object_id in sorted(objects):
        offsets[object_id] = len(output)
        output += f"{object_id} 0 obj\n".encode() + objects[object_id] + b"\nendobj\n"

    max_id = max(objects)
    xref_offset = len(output)
    output += f"xref\n0 {max_id + 1}\n".encode()
    output += b"0000000000 65535 f \n"
    for object_id in range(1, max_id + 1):
        output += f"{offsets.get(object_id, 0):010d} 00000 n \n".encode()
    output += (
        f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    ).encode()
    return bytes(output)
