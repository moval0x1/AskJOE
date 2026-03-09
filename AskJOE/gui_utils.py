# AskJOE GUI Utilities - Swing-based result viewer for Ghidra
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# Use from other scripts; no @runtime here to allow import without PyGhidra when testing

import re
import os

_ICON_IMAGE = None


def get_joes_icon():
    """
    Try to load JOES.png from the AskJOE package or its parent.
    Returns a java.awt.Image or None.
    """
    global _ICON_IMAGE
    if _ICON_IMAGE is not None:
        return _ICON_IMAGE
    try:
        from javax.imageio import ImageIO
        from java.io import File
    except Exception:
        return None
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(here, "JOES-black.png"),
            os.path.join(os.path.dirname(here), "JOES-black.png"),
            os.path.join(here, "JOES.png"),
            os.path.join(os.path.dirname(here), "JOES.png"),
        ]
        for p in candidates:
            if os.path.isfile(p):
                try:
                    _ICON_IMAGE = ImageIO.read(File(p))
                    return _ICON_IMAGE
                except Exception:
                    continue
    except Exception:
        return None
    return None

# -----------------------------------------------------------------------------
# AI response preprocessing (normalize before rendering)
# -----------------------------------------------------------------------------

def preprocess_ai_response(raw_text):
    """Normalize AI output for consistent markdown parsing and display."""
    if not raw_text or not isinstance(raw_text, str):
        return ""
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    # Collapse 3+ newlines to 2 for cleaner layout
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    # Remove lone trailing ``` some models add
    if text.endswith("\n```") or text.endswith("```"):
        text = re.sub(r"\n?```\s*$", "", text).strip()
    if text.startswith("```"):
        text = re.sub(r"^```\w*\n?", "", text)
    return text


# -----------------------------------------------------------------------------
# Markdown-like to HTML (for AI triage and other report text)
# -----------------------------------------------------------------------------

def _escape_html(text):
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _syntax_highlight_python(code_text):
    """
    Very lightweight Python syntax highlighter for HTML output.
    Not a full parser, but good enough for readability in JEditorPane.
    """
    if not code_text:
        return ""
    import re as _re

    # HTML-escape first so we never emit raw HTML from the code.
    s = _escape_html(code_text)

    # Strings (single and double quotes, no multi-line awareness)
    string_pattern = r'(\"[^\"\\]*(?:\\.[^\"\\]*)*\"|\'[^\'\\]*(?:\\.[^\'\\]*)*\')'
    s = _re.sub(string_pattern, r"<span class='py-str'>\1</span>", s)

    # Keywords
    py_keywords = (
        "False|None|True|and|as|assert|async|await|break|class|continue|def|del|elif|else|"
        "except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|"
        "return|try|while|with|yield"
    )
    kw_pattern = r"\b(" + py_keywords + r")\b"
    s = _re.sub(kw_pattern, r"<span class='py-kw'>\1</span>", s)

    # Numbers
    num_pattern = r"\b(\d+(?:\.\d*)?|\.\d+)\b"
    s = _re.sub(num_pattern, r"<span class='py-num'>\1</span>", s)

    # Comments – everything from # to end of line
    comment_pattern = r"(\#.*?$)"
    s = _re.sub(comment_pattern, r"<span class='py-comment'>\1</span>", s, flags=_re.MULTILINE)

    return s


def _syntax_highlight(code_text, lang_tag):
    """Dispatch to a simple syntax highlighter based on language tag."""
    if not lang_tag:
        return _escape_html(code_text or "")
    lang = (lang_tag or "").strip().lower()
    if lang in ("python", "py"):
        return _syntax_highlight_python(code_text or "")
    # Fallback: plain escaped code
    return _escape_html(code_text or "")


def markdown_like_to_html(raw_text):
    """
    Convert markdown-like AI output to HTML for display in JEditorPane.
    Handles: # ## ### headings, **bold** *italic* `code`, | tables, - * bullets,
    numbered lists (1. 2.), > blockquotes, ``` code blocks, --- rules.
    """
    if not raw_text or not isinstance(raw_text, str):
        return "<p>No content.</p>"

    lines = raw_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = []
    in_table = False
    table_rows = []
    i = 0

    in_ul = False
    in_ol = False

    def flush_table():
        nonlocal table_rows, out, in_table
        if not table_rows:
            return
        out.append("<table class='report-table'>")
        for row_idx, row in enumerate(table_rows):
            out.append("<tr>")
            tag = "th" if row_idx == 0 else "td"
            for cell in row:
                out.append("<{}>{}</{}>".format(tag, cell, tag))
            out.append("</tr>")
        out.append("</table>")
        table_rows = []
        in_table = False

    def flush_lists():
        nonlocal in_ul, in_ol, out
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Horizontal rule
        if stripped in ("---", "***", "___"):
            flush_table()
            flush_lists()
            out.append("<hr/>")
            i += 1
            continue

        # Fenced code block: ``` or ```python etc.
        if stripped.startswith("```"):
            flush_table()
            flush_lists()
            # Get optional language tag: ```python
            lang = stripped[3:].strip().lower() if len(stripped) > 3 else ""
            i += 1
            code_lines = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1  # skip closing ```
            code_text = "\n".join(code_lines)
            highlighted = _syntax_highlight(code_text, lang)
            cls = "code-block" + ((" code-" + lang) if lang else "")
            out.append("<pre class='{}'>".format(cls))
            out.append(highlighted)
            out.append("</pre>")
            continue

        # Table row: | ... |
        if "|" in line and stripped.startswith("|") and stripped.endswith("|"):
            flush_lists()
            if not in_table:
                flush_table()
            in_table = True
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            # Skip separator row (|---|---|)
            if all(re.match(r"^\-+$", c.strip()) for c in cells):
                i += 1
                continue
            cells = [_inline_md_to_html(c) for c in cells]
            table_rows.append(cells)
            i += 1
            continue

        if in_table:
            flush_table()
            in_table = False

        # Headings: # ## ### (inline style so Swing renders them)
        if stripped.startswith("###"):
            flush_lists()
            s = stripped.lstrip("#").strip()
            out.append("<h3 style='font-size:1.08em; color:#1976d2; margin:0.5em 0 0.25em 0; font-weight:600;'>{}</h3>".format(_inline_md_to_html(s)))
            i += 1
            continue
        if stripped.startswith("##"):
            flush_lists()
            s = stripped.lstrip("#").strip()
            out.append("<h2 style='font-size:1.2em; color:#1565c0; margin:0.65em 0 0.35em 0; font-weight:600;'>{}</h2>".format(_inline_md_to_html(s)))
            i += 1
            continue
        if stripped.startswith("#"):
            flush_lists()
            s = stripped.lstrip("#").strip()
            out.append("<h1 style='font-size:1.4em; color:#0d47a1; margin:0.75em 0 0.4em 0; border-bottom:2px solid #bbdefb; padding-bottom:6px; font-weight:600;'>{}</h1>".format(_inline_md_to_html(s)))
            i += 1
            continue

        # Blockquote: > ...
        if stripped.startswith("> "):
            flush_lists()
            out.append("<blockquote>{}</blockquote>".format(_inline_md_to_html(stripped[2:].strip())))
            i += 1
            continue
        if stripped.startswith(">"):
            flush_lists()
            out.append("<blockquote>{}</blockquote>".format(_inline_md_to_html(stripped[1:].strip())))
            i += 1
            continue

        # Numbered list 1. 2. etc.
        if re.match(r"^\s*\d+\.\s", line):
            if not in_ol:
                flush_lists()
                if in_ul:
                    out.append("</ul>")
                    in_ul = False
                out.append("<ol>")
                in_ol = True
            content = re.sub(r"^\s*\d+\.\s", "", stripped)
            out.append("<li>{}</li>".format(_inline_md_to_html(content)))
            i += 1
            continue

        # Bullet list
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_ul:
                flush_lists()
                if in_ol:
                    out.append("</ol>")
                    in_ol = False
                out.append("<ul>")
                in_ul = True
            out.append("<li>{}</li>".format(_inline_md_to_html(stripped[2:].strip())))
            i += 1
            continue

        # Empty line
        if not stripped:
            flush_lists()
            out.append("<p></p>")
            i += 1
            continue

        # Status lines: [+] success, [-] error, [!] warning (script-style output)
        if stripped.startswith("[+] "):
            flush_lists()
            rest = _inline_md_to_html(stripped[4:].strip())
            out.append("<p style='color:#2e7d32; margin:0.35em 0;'><b>[+]</b> {}</p>".format(rest))
            i += 1
            continue
        if stripped.startswith("[-] "):
            flush_lists()
            rest = _inline_md_to_html(stripped[4:].strip())
            out.append("<p style='color:#c62828; margin:0.35em 0;'><b>[-]</b> {}</p>".format(rest))
            i += 1
            continue
        if stripped.startswith("[!] "):
            flush_lists()
            rest = _inline_md_to_html(stripped[4:].strip())
            out.append("<p style='color:#e65100; margin:0.35em 0;'><b>[!]</b> {}</p>".format(rest))
            i += 1
            continue

        # Normal paragraph
        flush_lists()
        out.append("<p>{}</p>".format(_inline_md_to_html(stripped)))
        i += 1

    flush_table()
    flush_lists()

    html = "\n".join(out)
    return html


def _inline_md_to_html(s):
    """Convert inline markdown (e.g. **bold**) to HTML."""
    if not s:
        return ""
    s = _escape_html(s)
    # **bold**
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    # *italic*
    s = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", s)
    # `code`
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    # Hex addresses like 0x0040335a > clickable link (use http URL so JEditorPane fires HyperlinkEvent)
    def _addr_link(m):
        hex_part = m.group(1)
        addr_only = hex_part[2:] if hex_part.lower().startswith("0x") else hex_part
        return "<a href=\"http://ghidra.goto/{}\" style='color:#1565c0;text-decoration:underline;'>{}</a>".format(addr_only, hex_part)
    s = re.sub(r"\b(0x[0-9A-Fa-f]{5,})\b", _addr_link, s)
    return s


# -----------------------------------------------------------------------------
# Base CSS for the report viewer (readable font, clear sections)
# -----------------------------------------------------------------------------

_REPORT_CSS = """
body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  font-size: 13px;
  line-height: 1.6;
  color: #1a1a1a;
  background: #f0f2f5;
  padding: 16px 20px;
  margin: 0;
  max-width: 900px;
}
h1 {
  font-size: 1.4em; color: #0d47a1; margin: 0.75em 0 0.4em 0;
  border-bottom: 2px solid #bbdefb; padding-bottom: 6px; font-weight: 600;
}
h2 {
  font-size: 1.2em; color: #1565c0; margin: 0.65em 0 0.35em 0; font-weight: 600;
}
h3 {
  font-size: 1.08em; color: #1976d2; margin: 0.5em 0 0.25em 0; font-weight: 600;
}
p { margin: 0.4em 0; }
ul, ol {
  margin: 0.4em 0 0.4em 1.25em; padding-left: 1em;
}
ul { list-style-type: disc; }
ol { list-style-type: decimal; }
li { margin: 0.25em 0; }
blockquote {
  margin: 0.5em 0; padding: 8px 14px; border-left: 4px solid #1976d2;
  background: #e3f2fd; color: #0d47a1; border-radius: 0 4px 4px 0;
}
code {
  background: #e3f2fd; padding: 2px 6px; border-radius: 4px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 0.92em;
}
pre.code-block {
  background: #263238; color: #eeffff; padding: 14px 16px; border-radius: 6px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 12px;
  line-height: 1.5; overflow-x: auto; margin: 0.6em 0; white-space: pre;
  border: 1px solid #37474f; box-shadow: 0 1px 4px rgba(0,0,0,0.12);
}
/* Lightweight Python syntax highlighting */
pre.code-block.code-python .py-kw      { color: #c792ea; font-weight: 600; }
pre.code-block.code-python .py-str     { color: #c3e88d; }
pre.code-block.code-python .py-num     { color: #f78c6c; }
pre.code-block.code-python .py-comment { color: #546e7a; font-style: italic; }
a { color: #1565c0; text-decoration: underline; }
a:hover { color: #0d47a1; }
hr { border: none; border-top: 1px solid #90a4ae; margin: 1em 0; }
table.report-table {
  border-collapse: collapse; margin: 0.6em 0; font-size: 12px;
  background: #fff; border-radius: 6px; overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}
table.report-table th,
table.report-table td {
  border: 1px solid #e0e0e0; padding: 8px 12px; text-align: left;
}
table.report-table th {
  background: #1565c0; color: #fff; font-weight: 600;
}
table.report-table tr:nth-child(even) { background: #f8f9fa; }
table.report-table tr:hover { background: #e3f2fd; }
/* Script-style status lines (Tools tab and raw output) */
p.line-success { color: #2e7d32; margin: 0.35em 0; padding: 4px 0; }
p.line-success strong { color: #1b5e20; }
p.line-error   { color: #c62828; margin: 0.35em 0; padding: 4px 0; }
p.line-error strong { color: #b71c1c; }
p.line-warn   { color: #e65100; margin: 0.35em 0; padding: 4px 0; }
p.line-warn strong { color: #bf360c; }
"""


def script_output_to_html(raw_text):
    """
    Convert raw script output (e.g. [+] / [-] lines) to styled HTML.
    Use when output is plain text rather than markdown, so it still looks good.
    """
    if not raw_text or not isinstance(raw_text, str):
        return "<p>No output.</p>"
    lines = raw_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            out.append("<p></p>")
            continue
        escaped = _escape_html(stripped)
        if stripped.startswith("[+] "):
            rest = _escape_html(stripped[4:].strip())
            out.append("<p style='color:#2e7d32; margin:0.35em 0;'><b>[+]</b> {}</p>".format(rest))
        elif stripped.startswith("[-] "):
            rest = _escape_html(stripped[4:].strip())
            out.append("<p style='color:#c62828; margin:0.35em 0;'><b>[-]</b> {}</p>".format(rest))
        elif stripped.startswith("[!] "):
            rest = _escape_html(stripped[4:].strip())
            out.append("<p style='color:#e65100; margin:0.35em 0;'><b>[!]</b> {}</p>".format(rest))
        else:
            out.append("<p>{}</p>".format(escaped))
    return "\n".join(out) if out else "<p>No output.</p>"


def build_query_conversation_html(turns):
    """
    Build HTML body for the Query tab conversation.
    turns: list of {"role": "You"|"AskJOE", "text": "..."}
    AskJOE messages are rendered from markdown (headings, bold, lists, code).
    """
    out = []
    for t in turns:
        role = t.get("role", "")
        text = t.get("text", "") or ""
        if role == "You":
            escaped = _escape_html(text)
            out.append("<div style='margin:0.6em 0; padding:8px 12px; background:#e3f2fd; border-left:4px solid #1565c0;'><b style='color:#0d47a1;'>[You]</b> {}</div>".format(escaped.replace("\n", "<br>\n")))
        else:
            normalized = preprocess_ai_response(text)
            body = markdown_like_to_html(normalized)
            out.append("<div style='margin:0.6em 0;'><b style='color:#1565c0;'>[AskJOE]</b></div><div style='margin:0.25em 0 0.8em 1em;'>{}</div>".format(body))
    return "\n".join(out) if out else "<p style='color:#666;'>Send a message to start. Context from the loaded binary (current function + disassembly) is included automatically.</p>"


def _build_html_document(body_html, title="AskJOE Report"):
    # HTML 4.01 for Swing JEditorPane; inline styles so rendering works when <style> is ignored
    body_style = (
        "font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; "
        "font-size: 13px; line-height: 1.6; color: #1a1a1a; "
        "background: #f0f2f5; padding: 16px 20px; margin: 0;"
    )
    return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>{title}</title>
<style type="text/css">
{css}
</style>
</head>
<body style="{body_style}">
{body}
</body>
</html>""".format(
        title=_escape_html(title),
        css=_REPORT_CSS,
        body_style=body_style,
        body=body_html,
    )


# -----------------------------------------------------------------------------
# Show result in a Swing window (must run on EDT)
# -----------------------------------------------------------------------------

def show_triage_results(formatted_text, title="AI Triage Analysis Results"):
    """
    Show AI triage (or any markdown-like) report in a Swing window.
    Safe to call from PyGhidra; falls back to no-op if Swing is unavailable.
    """
    try:
        from java.awt import EventQueue, BorderLayout
        from javax.swing import (
            JFrame,
            JEditorPane,
            JScrollPane,
            WindowConstants,
        )
    except Exception:
        return False

    def _show():
        try:
            body_html = markdown_like_to_html(formatted_text)
            full_html = _build_html_document(body_html, title=title)

            frame = JFrame(title)
            try:
                icon = get_joes_icon()
                if icon is not None:
                    frame.setIconImage(icon)
            except Exception:
                pass
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
            frame.setSize(900, 700)
            frame.setLocationRelativeTo(None)

            editor = JEditorPane()
            editor.setEditable(False)

            # Write HTML to a temporary file and load via setPage(URL) so Swing
            # fully parses it (fixes blank/unstyled output on some setups).
            try:
                import tempfile
                import os as _os
                from java.net import URL
                fd, path = tempfile.mkstemp(suffix=".html", prefix="askjoe_triage_", text=True)
                try:
                    _os.write(fd, full_html.encode("utf-8"))
                finally:
                    _os.close(fd)
                normalized = path.replace("\\", "/")
                file_url = ("file://" + normalized) if normalized.startswith("/") else ("file:///" + normalized)
                editor.setContentType("text/html")
                try:
                    from javax.swing.text.html import HTMLEditorKit
                    editor.setEditorKit(HTMLEditorKit())
                except Exception:
                    pass
                editor.setPage(URL(file_url))
            except Exception:
                # Fallback: set HTML directly
                editor.setContentType("text/html")
                try:
                    from javax.swing.text.html import HTMLEditorKit
                    editor.setEditorKit(HTMLEditorKit())
                except Exception:
                    pass
                editor.setText(full_html)
                editor.setCaretPosition(0)

            scroll = JScrollPane(editor)
            scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
            scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)

            frame.getContentPane().add(scroll, BorderLayout.CENTER)
            frame.setVisible(True)
        except Exception as e:
            try:
                from ghidra.ghidra_builtins import println
                println("[-] GUI display failed: {}".format(e))
            except Exception:
                print("[-] GUI display failed: {}".format(e))

    try:
        if EventQueue.isDispatchThread():
            _show()
        else:
            EventQueue.invokeLater(_show)
        return True
    except Exception:
        return False


def show_text_in_gui(plain_text, title="AskJOE Output"):
    """Show plain text in a simple scrollable window (no markdown conversion)."""
    try:
        from java.awt import EventQueue, BorderLayout
        from javax.swing import (
            JFrame,
            JEditorPane,
            JScrollPane,
            WindowConstants,
        )
    except Exception:
        return False

    def _show():
        try:
            html = _build_html_document("<pre>{}</pre>".format(_escape_html(plain_text)), title=title)
            frame = JFrame(title)
            try:
                icon = get_joes_icon()
                if icon is not None:
                    frame.setIconImage(icon)
            except Exception:
                pass
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
            frame.setSize(800, 600)
            frame.setLocationRelativeTo(None)
            editor = JEditorPane()
            editor.setContentType("text/html")
            editor.setText(html)
            editor.setEditable(False)
            frame.getContentPane().add(JScrollPane(editor), BorderLayout.CENTER)
            frame.setVisible(True)
        except Exception as e:
            try:
                from ghidra.ghidra_builtins import println
                println("[-] GUI failed: {}".format(e))
            except Exception:
                print("[-] GUI failed: {}".format(e))

    try:
        if EventQueue.isDispatchThread():
            _show()
        else:
            EventQueue.invokeLater(_show)
        return True
    except Exception:
        return False


def show_result_in_window(content, title="AskJOE Result", is_html=True):
    """
    Show HTML or plain text in a new JFrame with JOES icon.
    Used for Func Simplifier, Threat Intel, etc. to open result in a dedicated window.
    """
    try:
        from java.awt import EventQueue, BorderLayout
        from javax.swing import (
            JFrame,
            JEditorPane,
            JScrollPane,
            WindowConstants,
        )
    except Exception:
        return False

    def _show():
        try:
            if is_html and content:
                try:
                    full_html = _build_html_document(content, title=title)
                except Exception:
                    full_html = content
            else:
                full_html = _build_html_document(
                    "<pre>{}</pre>".format(_escape_html(content or "")), title=title
                )

            frame = JFrame(title)
            try:
                icon = get_joes_icon()
                if icon is not None:
                    frame.setIconImage(icon)
            except Exception:
                pass
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
            frame.setSize(900, 700)
            frame.setLocationRelativeTo(None)

            editor = JEditorPane()
            editor.setEditable(False)
            editor.setContentType("text/html")
            try:
                from javax.swing.text.html import HTMLEditorKit
                editor.setEditorKit(HTMLEditorKit())
            except Exception:
                pass
            try:
                import tempfile
                import os as _os
                from java.net import URL
                fd, path = tempfile.mkstemp(suffix=".html", prefix="askjoe_result_", text=True)
                try:
                    _os.write(fd, full_html.encode("utf-8"))
                finally:
                    _os.close(fd)
                normalized = path.replace("\\", "/")
                file_url = ("file://" + normalized) if normalized.startswith("/") else ("file:///" + normalized)
                editor.setPage(URL(file_url))
            except Exception:
                editor.setText(full_html)
            editor.setCaretPosition(0)

            # Clickable addresses: handle http://ghidra.goto/ADDR and ghidra:goTo/ADDR (no Java inheritance)
            try:
                def _do_goto(addr_str):
                    addr_str = (addr_str or "").strip()
                    if not addr_str:
                        return
                    try:
                        from AskJOE.explain_utils import go_to_address_in_ghidra, get_program_and_address_from_code_browser
                        prog, _ = get_program_and_address_from_code_browser()
                        if not prog:
                            try:
                                from ghidra.ghidra_builtins import currentProgram
                                prog = currentProgram
                            except Exception:
                                pass
                        if prog:
                            go_to_address_in_ghidra(prog, addr_str)
                    except Exception:
                        pass

                class _GoToHyperlinkListener(object):
                    def hyperlinkUpdate(self, event):
                        try:
                            from javax.swing.event import HyperlinkEvent
                            if event.getEventType() != HyperlinkEvent.EventType.ACTIVATED:
                                return
                            url = event.getURL()
                            url_str = url.toString() if url else (event.getDescription() or "")
                            if not url_str:
                                return
                            if "ghidra.goto" in url_str or "ghidra:goTo" in url_str:
                                addr_str = url_str.split("/")[-1].split(":")[-1].strip()
                                if addr_str:
                                    _do_goto(addr_str)
                        except Exception:
                            pass

                editor.addHyperlinkListener(_GoToHyperlinkListener())
            except Exception:
                pass

            scroll = JScrollPane(editor)
            scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
            scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
            frame.getContentPane().add(scroll, BorderLayout.CENTER)
            frame.setVisible(True)
            try:
                frame.toFront()
                frame.requestFocus()
            except Exception:
                pass
        except Exception as e:
            try:
                from ghidra.ghidra_builtins import println
                println("[-] Result window failed: {}".format(e))
            except Exception:
                print("[-] Result window failed: {}".format(e))

    try:
        if EventQueue.isDispatchThread():
            _show()
        else:
            EventQueue.invokeLater(_show)
        return True
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Function graph results with clickable links (ghidra:goTo/ADDR)
# -----------------------------------------------------------------------------

def show_graph_results_in_gui(html_content, title="Function Graph", on_go_to_address=None):
    """
    Show function graph results in a Swing window (like AI Triage).
    When the user clicks a link with href="ghidra:goTo/ADDR", on_go_to_address(addr_str) is called.
    on_go_to_address should navigate to that address (e.g. program.getAddressFactory().getAddress(addr); goTo(addr)).
    """
    try:
        from java.awt import EventQueue, BorderLayout
        from javax.swing import (
            JFrame,
            JEditorPane,
            JScrollPane,
            WindowConstants,
        )
        from javax.swing.event import HyperlinkListener, HyperlinkEvent
    except Exception:
        return False

    def _show():
        try:
            full_html = _build_html_document(html_content, title=title)
            frame = JFrame(title)
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
            frame.setSize(900, 700)
            frame.setLocationRelativeTo(None)

            editor = JEditorPane()
            editor.setContentType("text/html")
            editor.setText(full_html)
            editor.setEditable(False)
            editor.setCaretPosition(0)

            if on_go_to_address and callable(on_go_to_address):

                class GoToLinkListener(HyperlinkListener):
                    def hyperlinkUpdate(self, event):
                        if event.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
                            url = event.getURL()
                            if url is None:
                                url_str = event.getDescription()
                            else:
                                url_str = url.toString()
                            if url_str and url_str.startswith("ghidra:goTo/"):
                                addr_str = url_str.replace("ghidra:goTo/", "").strip()
                                if addr_str:
                                    try:
                                        on_go_to_address(addr_str)
                                    except Exception as e:
                                        try:
                                            from ghidra.ghidra_builtins import println
                                            println("[-] GoTo failed for {}: {}".format(addr_str, e))
                                        except Exception:
                                            pass

                editor.addHyperlinkListener(GoToLinkListener())

            scroll = JScrollPane(editor)
            scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
            scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
            frame.getContentPane().add(scroll, BorderLayout.CENTER)
            frame.setVisible(True)
        except Exception as e:
            try:
                from ghidra.ghidra_builtins import println
                println("[-] Graph GUI failed: {}".format(e))
            except Exception:
                print("[-] Graph GUI failed: {}".format(e))

    try:
        if EventQueue.isDispatchThread():
            _show()
        else:
            EventQueue.invokeLater(_show)
        return True
    except Exception:
        return False
