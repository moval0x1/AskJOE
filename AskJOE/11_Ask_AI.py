#!/usr/bin/env python

# 11_Ask_AI.py – AskJOE interactive Ask AI tool
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @menupath Tools.SecurityJOES.Ask AI
# @toolbar JOES-black.png
# @runtime PyGhidra

"""
Standalone Ask AI chat for AskJOE.

Features:
  • Chat about the current binary with an AI assistant.
  • Automatically includes context: current function and nearby disassembly.
  • Supports macros in your question:
      - #func  – embed current function C code
      - #addr  – embed disassembly around the cursor
"""

import sys
import threading

try:
    from logging_utils import setup_logging
    _LOGGER, _LOG_PATH = setup_logging("ask_ai")
except Exception:
    _LOGGER, _LOG_PATH = None, None


def _log_exception(context, exc):
    if _LOGGER is not None:
        try:
            _LOGGER.exception("%s: %s", context, exc)
        except Exception:
            pass


def _get_ghidra_builtins():
    out = {}
    try:
        import ghidra.ghidra_builtins as _gb
        for name in dir(_gb):
            if not name.startswith("_"):
                out[name] = getattr(_gb, name)
    except Exception:
        pass
    for name in ("currentProgram", "currentAddress", "state", "getState", "println"):
        if name not in out and name in globals():
            out[name] = globals()[name]
    return out


def _get_live_prog_addr():
    """
    Best‑effort (program, address) for the current Code Browser cursor.
    """
    b = _get_ghidra_builtins()
    prog = b.get("currentProgram")
    addr = b.get("currentAddress")
    if prog is not None and addr is not None:
        return prog, addr
    try:
        st = b.get("state") or b.get("getState")
        if callable(st):
            st = st()
        if st is not None and hasattr(st, "getCurrentLocation"):
            loc = st.getCurrentLocation()
            if loc is not None:
                p, a = loc.getProgram(), loc.getAddress()
                if p is not None and a is not None:
                    return p, a
    except Exception:
        pass
    return prog, addr


def _show_ask_ai():
    b = _get_ghidra_builtins()
    println = b.get("println", lambda msg: None)

    try:
        from java.awt import BorderLayout, Dimension, Color, Insets, FlowLayout, EventQueue
        from javax.swing import (
            JFrame, JPanel, JScrollPane, JButton, JTextArea, JLabel, JEditorPane, JComboBox
        )
        from javax.swing.border import EmptyBorder, CompoundBorder, MatteBorder
    except Exception as e:
        println("[-] Ask AI GUI requires Swing: {}".format(e))
        return

    # Visual style – match main AskJOE light theme for readability
    PANEL_BG = Color(0xF2, 0xF4, 0xF8)      # light gray panel background
    CONTENT_BG = Color(0xFF, 0xFF, 0xFF)    # white content areas
    BTN_BG = Color(0xEE, 0xEE, 0xEE)        # light gray buttons
    BTN_FG = Color(0x00, 0x00, 0x00)        # black button text
    HINT = Color(0x33, 0x33, 0x33)          # dark gray hint text
    HINT_BG = Color(0xE8, 0xEE, 0xF7)       # soft blue-gray hint background
    HINT_ACCENT = Color(0x15, 0x65, 0xC0)   # blue accent bar

    frame = JFrame("AskJOE – Ask AI")
    try:
        from AskJOE.gui_utils import get_joes_icon
        _icon = get_joes_icon()
        if _icon is not None:
            frame.setIconImage(_icon)
    except Exception:
        pass
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    frame.setMinimumSize(Dimension(900, 500))

    root = JPanel(BorderLayout())
    root.setBackground(PANEL_BG)
    root.setBorder(EmptyBorder(12, 12, 12, 12))
    frame.add(root, BorderLayout.CENTER)

    # Conversation display
    query_turns = []  # list of {"role": "You"|"AskJOE", "text": "..."}

    query_display = JEditorPane()
    query_display.setContentType("text/html")
    query_display.setEditable(False)
    query_display.setMargin(Insets(8, 8, 8, 8))
    query_display.setBackground(CONTENT_BG)
    query_display.setForeground(Color(0x00, 0x00, 0x00))

    placeholder = (
        "<p style='color:#555;font-size:12px;'>"
        "Ask about the binary. Current function and disassembly are included automatically."
        "</p>"
    )
    query_display.setText(placeholder)
    root.add(JScrollPane(query_display), BorderLayout.CENTER)

    # Bottom area: hint + input + status
    bottom = JPanel(BorderLayout())
    bottom.setBackground(PANEL_BG)
    bottom.setBorder(EmptyBorder(10, 0, 0, 0))

    hint = JLabel(
        "<html><span style='color:#333333;'>Ask about the binary. Presets pull data from Ghidra for you (strings, imports, current function). Just pick a preset and click Send.</span></html>"
    )
    hint.setForeground(HINT)
    hint_wrap = JPanel(BorderLayout())
    hint_wrap.setBackground(HINT_BG)
    hint_wrap.setBorder(
        CompoundBorder(
            MatteBorder(0, 4, 0, 0, HINT_ACCENT),
            EmptyBorder(10, 14, 10, 14),
        )
    )
    hint_wrap.add(hint, BorderLayout.CENTER)

    # Preset questions: user sees only the instruction text. AskJOE injects Ghidra data automatically.
    PRESET_LABELS = [
        "Choose preset…",
        "Classify malware behavior",
        "Hunt C2 / exfil",
        "Summarize suspected config",
        "Find anti-debug / anti-VM",
        "Review interesting strings",
    ]
    PRESET_TEMPLATES = {
        "Classify malware behavior": (
            "Classify what kind of malware behavior this binary implements.\n"
            "Focus on:\n"
            "- Overall role (loader, infostealer, banker, ransomware, backdoor, downloader, etc.)\n"
            "- Key capabilities (persistence, credential theft, lateral movement, C2, data theft)\n"
            "- Most important APIs, constants, and strings that support this classification\n"
            "- 2–3 short bullets an analyst could paste into a report."
        ),
        "Hunt C2 / exfil": (
            "Look for anything related to command-and-control or data exfiltration in this binary:\n"
            "- Network APIs, URLs, domains, IPs, ports, HTTP paths\n"
            "- Crypto or encoding around network usage\n"
            "- Hardcoded keys, IVs, or beacons\n"
            "Point out the most suspicious addresses and explain why."
        ),
        "Summarize suspected config": (
            "Treat the code as configuration handling. Describe what configuration fields exist "
            "(keys, domains, mutexes, flags, etc.), where they are stored in memory, "
            "and how they might be decoded or decrypted."
        ),
        "Find anti-debug / anti-VM": (
            "Identify any anti-debugging, anti-VM, or sandbox-evasion behavior in this binary.\n"
            "Mention specific APIs, instructions, or checks (timing, CPUID, process names, drivers, etc.) "
            "and explain how an analyst could bypass or patch them."
        ),
        "Review interesting strings": (
            "Focus on strings that are useful for triage and hunting in this binary.\n"
            "Prioritise:\n"
            "- Network-related strings (domains, URLs, IPs, user-agents, API paths).\n"
            "- File system and registry paths, service / driver names, mutexes, event names.\n"
            "- Encryption keys, format strings, error messages, and anything that looks like config.\n"
            "Group findings into short bullets an analyst can paste into notes, and mention which ones are strongest IOCs or pivot points."
        ),
    }
    # For each preset, AskJOE injects this Ghidra context automatically when the user clicks Send (user does nothing).
    PRESET_EXTRA_MACROS = {
        "Classify malware behavior": "#imports\n#strings",
        "Hunt C2 / exfil": "#imports\n#strings",
        "Summarize suspected config": "#strings",
        "Find anti-debug / anti-VM": "#imports",
        "Review interesting strings": "#strings",
    }
    last_selected_preset = [None]  # mutable so on_send can read it
    preset_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 4))
    preset_panel.setBackground(HINT_BG)
    preset_label = JLabel("Preset:")
    preset_label.setForeground(HINT)
    preset_box = JComboBox(PRESET_LABELS)
    # Light background + black text for readability
    preset_box.setBackground(Color(0xEE, 0xEE, 0xEE))
    preset_box.setForeground(Color(0x00, 0x00, 0x00))
    preset_panel.add(preset_label)
    preset_panel.add(preset_box)

    north_panel = JPanel(BorderLayout())
    north_panel.setBackground(HINT_BG)
    north_panel.add(hint_wrap, BorderLayout.CENTER)
    north_panel.add(preset_panel, BorderLayout.SOUTH)

    bottom.add(north_panel, BorderLayout.NORTH)

    query_input = JTextArea(4, 50)
    query_input.setLineWrap(True)
    query_input.setWrapStyleWord(True)
    query_input.setMargin(Insets(6, 8, 6, 8))
    query_input.setToolTipText(
        "Type your question or pick a preset. AskJOE injects binary data (strings, imports, current function) automatically when you use a preset. Click Send to submit."
    )
    query_input.setBackground(CONTENT_BG)
    query_input.setForeground(Color(0x00, 0x00, 0x00))
    query_input_scroll = JScrollPane(query_input)
    query_input_scroll.setPreferredSize(Dimension(480, 88))

    send_btn = JButton("Send")
    send_btn.setToolTipText("Send the question to the AI")
    send_btn.setBackground(BTN_BG)
    send_btn.setForeground(BTN_FG)
    send_btn.setOpaque(True)
    send_btn.setContentAreaFilled(True)

    bookmark_btn = JButton("Bookmark here")
    bookmark_btn.setToolTipText("Create an AskJOE NOTE bookmark at the current cursor location")
    bookmark_btn.setBackground(BTN_BG)
    bookmark_btn.setForeground(BTN_FG)
    bookmark_btn.setOpaque(True)
    bookmark_btn.setContentAreaFilled(True)

    comment_btn = JButton("Comment here")
    comment_btn.setToolTipText("Add a repeatable comment at the current cursor location from the last AskJOE answer")
    comment_btn.setBackground(BTN_BG)
    comment_btn.setForeground(BTN_FG)
    comment_btn.setOpaque(True)
    comment_btn.setContentAreaFilled(True)

    row = JPanel(BorderLayout())
    row.setBackground(PANEL_BG)
    row.add(query_input_scroll, BorderLayout.CENTER)
    btn_wrap = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
    btn_wrap.setBackground(PANEL_BG)
    btn_wrap.add(send_btn)
    btn_wrap.add(bookmark_btn)
    btn_wrap.add(comment_btn)
    row.add(btn_wrap, BorderLayout.EAST)
    bottom.add(row, BorderLayout.CENTER)

    status = JLabel(
        "Type a question and click Send. Current function + disassembly are included automatically."
    )
    status.setForeground(HINT)
    status.setBorder(EmptyBorder(4, 0, 0, 0))
    bottom.add(status, BorderLayout.SOUTH)

    root.add(bottom, BorderLayout.SOUTH)

    # Helpers
    def render_conversation():
        """Render the conversation as HTML using AskJOE's markdown-like styling."""
        try:
            from AskJOE.gui_utils import build_query_conversation_html, _build_html_document
            from java.net import URL
            import tempfile
            import os as _os

            body = build_query_conversation_html(query_turns)
            full_html = _build_html_document(body, title="AskJOE Ask AI")

            # Write to a temp file and load via setPage(URL) so Swing parses it properly.
            fd, path = tempfile.mkstemp(suffix=".html", prefix="askjoe_askai_", text=True)
            try:
                _os.write(fd, full_html.encode("utf-8"))
            finally:
                _os.close(fd)
            normalized = path.replace("\\", "/")
            file_url = ("file://" + normalized) if normalized.startswith("/") else ("file:///" + normalized)

            query_display.setContentType("text/html")
            try:
                from javax.swing.text.html import HTMLEditorKit
                query_display.setEditorKit(HTMLEditorKit())
            except Exception:
                pass
            query_display.setPage(URL(file_url))
            query_display.setCaretPosition(query_display.getDocument().getLength())
        except Exception:
            # Fallback: simple plain-text rendering
            lines = []
            for t in query_turns:
                role = t.get("role", "")
                text = (t.get("text", "") or "").replace("\n", "\n  ")
                lines.append("[{}] {}".format(role, text))
            query_display.setContentType("text/plain")
            query_display.setText("\n\n".join(lines))
            query_display.setCaretPosition(len(query_display.getText()))

    def on_send(_e=None):
        msg = query_input.getText()
        if not msg or not msg.strip():
            return
        query_input.setText("")

        # AskJOE injects Ghidra data automatically when a preset was used (user does nothing).
        effective_message = msg.strip()
        if last_selected_preset[0] and last_selected_preset[0] in PRESET_EXTRA_MACROS:
            effective_message = effective_message + "\n\n" + PRESET_EXTRA_MACROS[last_selected_preset[0]]

        prog, addr = _get_live_prog_addr()
        if not prog or not addr:
            query_turns.append({"role": "You", "text": msg})
            query_turns.append(
                {
                    "role": "AskJOE",
                    "text": "Open a program and place the cursor first so context "
                    "(current function + disassembly) can be included.",
                }
            )
            render_conversation()
            try:
                status.setText(
                    "Open a program and place the cursor in a function, then ask your question again."
                )
            except Exception:
                pass
            return

        try:
            # Ensure AskJOE package is importable
            import os

            script_dir = os.path.dirname(__file__)
            repo_root = os.path.dirname(script_dir)
            if repo_root not in sys.path:
                sys.path.insert(0, repo_root)

            from AskJOE.explain_utils import resolve_query_macros, build_query_prompt

            resolved, context_parts = resolve_query_macros(prog, addr, effective_message)
            full_prompt = build_query_prompt(resolved, context_parts)
        except Exception as ex:
            _log_exception("Error building Ask AI context", ex)
            query_turns.append({"role": "You", "text": msg})
            query_turns.append(
                {
                    "role": "AskJOE",
                    "text": "Error building context. See latest log in AskJOE/logs for details.",
                }
            )
            render_conversation()
            return

        query_turns.append({"role": "You", "text": msg})
        query_turns.append({"role": "AskJOE", "text": "Thinking..."})
        render_conversation()
        try:
            status.setText("Question sent to AI. Waiting for a response...")
        except Exception:
            pass

        def worker():
            try:
                from AskJOE.ai_utils import ask_open_ai, parse_open_ai_response

                resp = ask_open_ai(full_prompt)
                text = parse_open_ai_response(resp) if resp else "No response from AI."
            except Exception as e:
                _log_exception("Ask AI request failed", e)
                text = "Error while asking AI. See latest log in AskJOE/logs for details."

            def ui_update():
                if query_turns and query_turns[-1].get("text") == "Thinking...":
                    query_turns[-1] = {"role": "AskJOE", "text": text}
                else:
                    query_turns.append({"role": "AskJOE", "text": text})
                render_conversation()
                try:
                    status.setText("Answer received. Review the explanation above.")
                except Exception:
                    pass

            if EventQueue.isDispatchThread():
                ui_update()
            else:
                EventQueue.invokeLater(ui_update)

        threading.Thread(target=worker, name="AskJOE-AskAI", daemon=True).start()

    send_btn.addActionListener(on_send)

    def on_preset_selected(_e=None):
        try:
            label = preset_box.getSelectedItem()
        except Exception:
            label = None
        if not label or label == "Choose preset…":
            last_selected_preset[0] = None
            return
        if label not in PRESET_TEMPLATES:
            return
        last_selected_preset[0] = label
        template = PRESET_TEMPLATES.get(label, "")
        if template:
            query_input.setText(template)
            query_input.requestFocus()

    preset_box.addActionListener(on_preset_selected)

    def _get_latest_ai_answer():
        """Return text of the last AskJOE answer (or None)."""
        for entry in reversed(query_turns):
            if entry.get("role") == "AskJOE":
                return entry.get("text") or ""
        return ""

    def _make_bookmark_note():
        """Create a NOTE bookmark at the current location with a short summary of the last AI answer."""
        prog, addr = _get_live_prog_addr()
        if not prog or not addr:
            status.setText("No live program/address. Move the cursor in CodeBrowser and try again.")
            return
        note_text = _get_latest_ai_answer().strip()
        if not note_text:
            status.setText("No AskJOE answer to bookmark yet. Ask a question first.")
            return
        if len(note_text) > 160:
            note_text = note_text[:157] + "..."
        try:
            from ghidra.program.model.listing import BookmarkType
            bm = prog.getBookmarkManager()
            bm.setBookmark(addr, BookmarkType.NOTE, "AskJOE", note_text)
            status.setText("Bookmark added at {} (AskJOE NOTE).".format(addr))
        except Exception as ex:
            _log_exception("Failed to create bookmark from Ask AI", ex)
            status.setText("Could not create bookmark. See latest log in AskJOE/logs for details.")

    def _make_repeatable_comment():
        """Add a repeatable comment at the current location from the last AI answer."""
        prog, addr = _get_live_prog_addr()
        if not prog or not addr:
            status.setText("No live program/address. Move the cursor in CodeBrowser and try again.")
            return
        comment_text = _get_latest_ai_answer().strip()
        if not comment_text:
            status.setText("No AskJOE answer to comment yet. Ask a question first.")
            return
        if len(comment_text) > 256:
            comment_text = comment_text[:253] + "..."
        try:
            from ghidra.program.model.listing import CodeUnit
            listing = prog.getListing()
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                status.setText("No code unit at {} to attach a comment.".format(addr))
                return
            cu.setComment(CodeUnit.REPEATABLE_COMMENT, "AskJOE: " + comment_text)
            status.setText("Repeatable comment added at {} from AskJOE answer.".format(addr))
        except Exception as ex:
            _log_exception("Failed to create repeatable comment from Ask AI", ex)
            status.setText("Could not create comment. See latest log in AskJOE/logs for details.")

    bookmark_btn.addActionListener(lambda _e: _make_bookmark_note())
    comment_btn.addActionListener(lambda _e: _make_repeatable_comment())

    frame.pack()
    frame.setLocationRelativeTo(None)
    frame.setVisible(True)


if __name__ == "__main__":
    _show_ask_ai()

