#!/usr/bin/env python3
"""Convert a Markdown file to PDF using the markdown and weasyprint libraries."""

import argparse
import sys
from pathlib import Path

try:
    import markdown
    from weasyprint import HTML, CSS
except ImportError as e:
    print(f"error: {e}", file=sys.stderr)
    print("Install missing packages with:", file=sys.stderr)
    print("  pip install markdown weasyprint", file=sys.stderr)
    sys.exit(1)

CSS_STYLE = CSS(string="""
    @page {
        margin: 2cm 2.5cm;
        @bottom-right { content: counter(page) " / " counter(pages); font-size: 9pt; color: #666; }
    }
    body {
        font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif;
        font-size: 11pt;
        line-height: 1.6;
        color: #1a1a1a;
    }
    h1 { font-size: 22pt; border-bottom: 2px solid #333; padding-bottom: 4px; margin-top: 0; }
    h2 { font-size: 16pt; border-bottom: 1px solid #ccc; padding-bottom: 2px; margin-top: 1.4em; }
    h3 { font-size: 13pt; margin-top: 1.2em; }
    h4, h5, h6 { font-size: 11pt; margin-top: 1em; }
    code {
        font-family: "DejaVu Sans Mono", "Liberation Mono", monospace;
        font-size: 9.5pt;
        background: #f4f4f4;
        padding: 1px 4px;
        border-radius: 3px;
    }
    pre {
        background: #f4f4f4;
        border: 1px solid #ddd;
        border-left: 4px solid #888;
        padding: 10px 12px;
        overflow-x: auto;
        line-height: 1.4;
        page-break-inside: avoid;
    }
    pre code {
        background: none;
        padding: 0;
        border-radius: 0;
        font-size: 9pt;
    }
    table {
        border-collapse: collapse;
        width: 100%;
        margin: 1em 0;
        font-size: 10pt;
        page-break-inside: avoid;
    }
    th { background: #333; color: #fff; padding: 6px 10px; text-align: left; }
    td { padding: 5px 10px; border-bottom: 1px solid #ddd; }
    tr:nth-child(even) td { background: #f9f9f9; }
    blockquote {
        border-left: 4px solid #aaa;
        margin: 0.5em 0;
        padding: 4px 12px;
        color: #555;
        background: #fafafa;
    }
    a { color: #0066cc; }
    hr { border: none; border-top: 1px solid #ccc; margin: 1.5em 0; }
    ul, ol { padding-left: 1.5em; }
    li { margin-bottom: 0.2em; }
""")

MD_EXTENSIONS = [
    "extra",        # tables, fenced code, footnotes, attr_list
    "codehilite",   # syntax highlighting
    "toc",          # table of contents anchors
    "sane_lists",   # predictable list behaviour
    "smarty",       # smart quotes / dashes
]


def convert(input_path: Path, output_path: Path) -> None:
    source = input_path.read_text(encoding="utf-8")
    html_body = markdown.markdown(
        source,
        extensions=MD_EXTENSIONS,
        extension_configs={"codehilite": {"guess_lang": False}},
    )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{input_path.stem}</title></head>
<body>{html_body}</body>
</html>"""
    # write_pdf() renders the HTML via WeasyPrint's layout engine and writes a PDF
    HTML(string=html, base_url=str(input_path.parent)).write_pdf(
        str(output_path), stylesheets=[CSS_STYLE]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Markdown to PDF")
    parser.add_argument("input", help="Input Markdown file (e.g. ~/IR_FINDINGS.md)")
    parser.add_argument("-o", "--output", help="Output PDF path (default: same name, .pdf)")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"error: file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else input_path.with_suffix(".pdf")
    )

    print(f"Converting {input_path} → {output_path}")
    convert(input_path, output_path)
    print("Done.")


if __name__ == "__main__":
    main()
