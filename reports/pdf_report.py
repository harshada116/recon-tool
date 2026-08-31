"""Renders the standalone PDF report template to PDF bytes via WeasyPrint."""

import io


def render_pdf(html_string: str) -> bytes:
    from weasyprint import HTML  # imported lazily: heavy optional dependency

    buf = io.BytesIO()
    HTML(string=html_string).write_pdf(buf)
    return buf.getvalue()
