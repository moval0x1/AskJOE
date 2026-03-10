# AskJOE – AI-assisted reverse engineering for Ghidra
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @menupath Tools.SecurityJOES.AskJOE
# @keybinding CTRL SHIFT J
# @toolbar JOES-black.png
# @runtime PyGhidra

"""
AskJOE brings AI-augmented analysis and automation to Ghidra in one place.

**Analysis tab** – Run analysis, detectors, and helpers on the current binary:
  • AI Triage – Light or deep AI triage with MITRE ATT&CK-style findings  
  • CAPA Analysis – Malware capabilities via capa rules  
  • Explain Function – AI explanation of the function at the cursor (place cursor inside the function first)  
  • Threat Intel – Hash lookups and context (VirusTotal, etc.)  
  • Func Simplifier – AI simplification of complex functions  
  • Crypto Detector – Cryptographic constants and algorithms (RC4, AES, ChaCha20, etc.)  
  • Stack Strings / XOR Search – Recover stack-based and XOR-obfuscated strings  
  • Rename helper – AI-assisted renaming of functions and variables  
  • Ask AI – Chat about the binary; use **#func** to inject current function code and **#addr** for disassembly around the cursor  
  • Export report – Generate a consolidated HTML report from previous analysis runs

Open a binary (File > Import) before using Explain, Ask AI, or tools that need a program.
"""

import os
import sys
import json
import math
import threading
import tempfile


# Paths: support (A) AskJOE.py in repo root with AskJOE/ beside it, or (B) AskJOE.py inside AskJOE/
_script_file = globals().get("__file__") or getattr(sys.modules.get("__main__"), "__file__", None)
if _script_file:
    _SCRIPT_DIR = os.path.normpath(os.path.abspath(os.path.dirname(os.path.abspath(_script_file))))
else:
    _SCRIPT_DIR = os.path.normpath(os.path.abspath(os.getcwd()))
# _ASKJOE_DIR = folder containing config.ini and logging_utils.py (AskJOE package root; no pyfiles subdir)
if (os.path.isfile(os.path.join(_SCRIPT_DIR, "config.ini")) and
        os.path.isfile(os.path.join(_SCRIPT_DIR, "logging_utils.py"))):
    _ASKJOE_DIR = os.path.normpath(_SCRIPT_DIR)
else:
    _ASKJOE_DIR = os.path.normpath(os.path.join(_SCRIPT_DIR, "AskJOE"))
# If AskJOE dir doesn't have logging_utils.py (e.g. wrong __file__), try to find it via sys.path
if not os.path.isfile(os.path.join(_ASKJOE_DIR, "logging_utils.py")):
    for _p in list(sys.path):
        try:
            _p = os.path.normpath(os.path.abspath(_p or ""))
            _candidate = os.path.join(_p, "AskJOE")
            if os.path.isfile(os.path.join(_candidate, "logging_utils.py")):
                _ASKJOE_DIR = _candidate
                break
        except Exception:
            pass
# Scripts live in AskJOE/ directly (no pyfiles subfolder)
_ASKJOE_SCRIPTS_DIR = _ASKJOE_DIR
# Repo root = parent of AskJOE (so "import AskJOE" works). Only the repo root must be on sys.path,
# not the AskJOE folder itself, else Jython can resolve "AskJOE" as the folder and break submodule imports.
_ASKJOE_REPO_ROOT = os.path.dirname(_ASKJOE_DIR)
if _ASKJOE_REPO_ROOT and _ASKJOE_REPO_ROOT not in sys.path:
    sys.path.insert(0, os.path.normpath(_ASKJOE_REPO_ROOT))
# Do not add _SCRIPT_DIR if it is the AskJOE folder (would add AskJOE/ to path and break AskJOE.logging_utils)
if _SCRIPT_DIR and _SCRIPT_DIR not in sys.path and os.path.normpath(_SCRIPT_DIR) != os.path.normpath(_ASKJOE_DIR):
    sys.path.insert(0, _SCRIPT_DIR)

def _dummy_monitor():
    """No-op monitor for scripts run from launcher when getMonitor() is unavailable or returns None."""
    class _Dummy(object):
        def setMessage(self, msg): pass
        def isCancelled(self): return False
        def setProgress(self, v): pass
        def setMaximum(self, v): pass
    return _Dummy()

# Registry of tools: (display name, script filename in AskJOE/)
# Order: AI overview & helpers > detectors > graph/export
TOOLS = [
    # AI overview & helpers
    ("AI Triage", "01_AI_Triage_Analysis.py"),
    ("Ask AI", "11_Ask_AI.py"),
    ("Explain Function", "03_Explain_Function.py"),
    ("Func Simplifier", "04_Function_Simplifier.py"),
    ("Rename helper", "10_Rename_Helper.py"),
    # Detectors & enrichment
    ("CAPA Analysis", "02_CAPA_Analysis.py"),
    ("Threat Intel", "08_Threat_Intelligence_Analyzer.py"),
    ("Crypto Detector", "05_Crypto_Detector.py"),
    ("Stack Strings", "06_Stack_Strings_Detector.py"),
    ("XOR Search", "07_XOR_Searcher.py"),
    # Export / reporting
    ("Export report", "12_Export_Report.py"),
]


def _get_ghidra_builtins():
    """Build a dict of Ghidra builtins (currentProgram, getMonitor, println, etc.) from current context."""
    out = {}
    try:
        import ghidra.ghidra_builtins as _gb
        for name in dir(_gb):
            if not name.startswith("_"):
                out[name] = getattr(_gb, name)
    except Exception:
        pass
    for name in ("currentProgram", "getMonitor", "println", "currentAddress", "currentLocation",
                 "currentSelection", "currentHighlight", "state", "askProjectFolder", "askDirectory",
                 "askFile", "askString", "askChoice", "askYesNo", "getScriptName", "getSourceFile",
                 "getState", "createData", "createLabel", "setCurrentLocation", "setCurrentSelection",
                 "setHighlight", "setCursorHighlight", "setBackgroundColor", "setAnalysisOptions"):
        if name not in out and name in globals():
            out[name] = globals()[name]
    # Ensure getMonitor and monitor never missing: fallback to dummy so scripts can call monitor.setMessage()
    if "getMonitor" not in out or not callable(out.get("getMonitor")):
        out["getMonitor"] = _dummy_monitor
    if out.get("monitor") is None or (callable(out.get("getMonitor")) and out.get("getMonitor")() is None):
        out["monitor"] = _dummy_monitor()
    return out


def _run_script(script_path, capture_list, result_callback, builtins=None):
    """Thin wrapper that delegates to AskJOE.tool_runner.run_script."""
    from AskJOE import tool_runner

    if builtins is None:
        builtins = _get_ghidra_builtins()
    tool_runner.run_script(script_path, capture_list, result_callback, builtins, _ASKJOE_REPO_ROOT)


def _set_pane_html_via_file(pane, html):
    """
    Set HTML on a JEditorPane by writing to a temp file and loading via setPage(URL).
    This forces the HTMLEditorKit to parse and render (fixes Ghidra showing raw text).
    """
    try:
        fd, path = tempfile.mkstemp(suffix=".html", prefix="askjoe_", text=True)
        try:
            os.write(fd, html.encode("utf-8"))
        finally:
            os.close(fd)
        normalized = path.replace("\\", "/")
        file_url = ("file://" + normalized) if normalized.startswith("/") else ("file:///" + normalized)
        from java.net import URL
        pane.setContentType("text/html")
        try:
            from javax.swing.text.html import HTMLEditorKit
            pane.setEditorKit(HTMLEditorKit())
        except Exception:
            pass
        pane.setPage(URL(file_url))
        pane.setCaretPosition(0)
    except Exception:
        pane.setContentType("text/html")
        try:
            from javax.swing.text.html import HTMLEditorKit
            pane.setEditorKit(HTMLEditorKit())
        except Exception:
            pass
        pane.setText(html)
        pane.setCaretPosition(0)


def _show_launcher_gui():
    """Show the AskJOE tabbed window (Analysis | Rename helper | Ask AI | Config) with icon and improved UX."""
    try:
        from java.awt import EventQueue, BorderLayout, Dimension, Color, Insets, FlowLayout, Point, Font
        from java.awt.event import MouseListener, MouseMotionListener, MouseWheelListener, ActionListener, MouseAdapter
        from java.awt.event import ItemListener, ItemEvent, FocusListener
        from javax.swing import (
            JFrame, JPanel, JScrollPane, JButton, JTextArea, JLabel, JTextField,
            WindowConstants, JTabbedPane, JEditorPane, JOptionPane, ImageIcon, BoxLayout, Box,
            JTable, JComboBox, JCheckBox, JPasswordField,
        )
        from javax.swing.border import EmptyBorder, CompoundBorder, MatteBorder
        from javax.swing.table import DefaultTableModel
        from javax.swing import ListSelectionModel
        from java.awt import GridBagLayout, GridBagConstraints
        from javax.swing.event import HyperlinkListener, HyperlinkEvent
    except Exception as e:
        println("[-] AskJOE GUI requires Swing: {}".format(e))
        return


    # SecurityJOES brand colors (website uses black header)
    JOES_HEADER_BG = Color(0x00, 0x00, 0x00)      # black (per website)
    JOES_BTN_BG = Color(0xEE, 0xEE, 0xEE)        # light gray button background
    JOES_BTN_FG = Color(0x00, 0x00, 0x00)         # black button text (readable)
    JOES_SUBTITLE = Color(0xB3, 0xC7, 0xE6)       # light blue/gray text on header
    JOES_PANEL_BG = Color(0xF2, 0xF4, 0xF8)       # light gray background
    JOES_CONTENT_BG = Color(0xFF, 0xFF, 0xFF)     # white content areas
    JOES_HINT = Color(0x33, 0x33, 0x33)           # dark gray hint text (readable)
    JOES_HINT_BG = Color(0xE8, 0xEE, 0xF7)        # soft blue-gray for hint callout
    JOES_HINT_ACCENT = Color(0x15, 0x65, 0xC0)    # blue accent bar (matches report links)

    # Logo (main launcher header): prefer JOES.png, fallback to JOES-black.png
    _icon_image = None
    for _ip in [
        os.path.join(_SCRIPT_DIR, "JOES.png"),
        os.path.join(_ASKJOE_DIR, "JOES.png"),
        os.path.join(_SCRIPT_DIR, "JOES-black.png"),
        os.path.join(_ASKJOE_DIR, "JOES-black.png"),
    ]:
        if os.path.isfile(_ip):
            try:
                from javax.imageio import ImageIO
                from java.io import File
                _icon_image = ImageIO.read(File(_ip))
                break
            except Exception:
                pass

    # Capture program/address at open (user can re-open window to refresh)
    try:
        _prog = currentProgram
        _addr = currentAddress
    except Exception:
        _prog = None
        _addr = None

    tool_names = [t[0] for t in TOOLS]
    tool_paths = [os.path.abspath(os.path.join(_ASKJOE_SCRIPTS_DIR, t[1])) for t in TOOLS]

    frame = JFrame("AskJOE – SecurityJOES Tools")
    frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
    frame.setSize(980, 700)
    frame.setLocationRelativeTo(None)
    if _icon_image is not None:
        try:
            # Frame icon with black background (for taskbar/title bar)
            from java.awt.image import BufferedImage
            _w = _icon_image.getWidth(None)
            _h = _icon_image.getHeight(None)
            _icon_w, _icon_h = 32, 32
            _icon_black = BufferedImage(_icon_w, _icon_h, BufferedImage.TYPE_INT_ARGB)
            _g2 = _icon_black.createGraphics()
            try:
                _g2.setColor(Color(0, 0, 0))
                _g2.fillRect(0, 0, _icon_w, _icon_h)
                _g2.drawImage(_icon_image, 0, 0, _icon_w, _icon_h, 0, 0, _w, _h, None)
            finally:
                _g2.dispose()
            frame.setIconImage(_icon_black)
        except Exception:
            try:
                frame.setIconImage(_icon_image)
            except Exception:
                pass

    # Main content: optional header + tabs (SecurityJOES branding)
    main_content = JPanel(BorderLayout())
    main_content.setBackground(JOES_PANEL_BG)
    main_content.setBorder(EmptyBorder(0, 0, 0, 0))

    # Header with logo area and title (official JOES look)
    header = JPanel(FlowLayout(FlowLayout.LEFT, 12, 8))
    header.setBackground(JOES_HEADER_BG)
    header.setBorder(EmptyBorder(10, 14, 10, 14))
    if _icon_image is not None:
        try:
            _icon_label = JLabel(ImageIcon(_icon_image))
            _icon_label.setBorder(EmptyBorder(0, 0, 0, 12))
            header.add(_icon_label)
        except Exception:
            pass
    title_panel = JPanel()
    title_panel.setLayout(BoxLayout(title_panel, BoxLayout.Y_AXIS))
    title_panel.setOpaque(False)
    title_label = JLabel("AskJOE")
    title_label.setFont(title_label.getFont().deriveFont(22.0))
    title_label.setForeground(Color.WHITE)
    title_panel.add(title_label)
    sub_label = JLabel("SecurityJOES – AI-assisted reverse engineering")
    sub_label.setForeground(JOES_SUBTITLE)
    sub_label.setFont(sub_label.getFont().deriveFont(11.0))
    title_panel.add(sub_label)
    header.add(title_panel)
    main_content.add(header, BorderLayout.NORTH)

    tabs = JTabbedPane()

    # ----- Tools: one tab per tool -----
    tools_outer = JPanel(BorderLayout())
    tools_outer.setBackground(JOES_PANEL_BG)
    tools_outer.setBorder(EmptyBorder(12, 12, 12, 12))
    tools_inner_tabs = JTabbedPane()
    tools_status = JLabel("Select an analysis tool above, then click Run. Open a program first for analysis tools.")
    tools_status.setForeground(JOES_HINT)
    tools_status.setBorder(EmptyBorder(4, 0, 0, 0))
    for idx, (name, script_file) in enumerate(TOOLS):
        path = tool_paths[idx]
        tab_panel = JPanel(BorderLayout())
        tab_panel.setBackground(JOES_PANEL_BG)
        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        btn_row.setBackground(JOES_PANEL_BG)
        run_btn = JButton("Run")
        run_btn.setToolTipText("Execute this tool on the current program")
        run_btn.setBackground(JOES_BTN_BG)
        run_btn.setForeground(JOES_BTN_FG)
        run_btn.setOpaque(True)
        run_btn.setContentAreaFilled(True)
        run_btn.setBorderPainted(True)
        clear_btn = JButton("Clear output")
        clear_btn.setToolTipText("Clear the output pane")
        clear_btn.setForeground(JOES_BTN_FG)
        clear_btn.setBackground(JOES_BTN_BG)
        clear_btn.setOpaque(True)
        result_area = JEditorPane()
        result_area.setContentType("text/html")
        result_area.setEditable(False)
        result_area.setBackground(JOES_CONTENT_BG)
        result_area.setText("<p style='color:#555;'>Click <b>Run</b> to execute this tool.</p>")

        # Clickable addresses: handle link clicks (ghidra.goto/ADDR) and plain-text 0xADDR clicks
        try:
            from AskJOE.explain_utils import go_to_address_in_ghidra

            def _goto_addr(addr_str):
                addr_str = (addr_str or "").strip()
                if not addr_str:
                    return
                prog = _get_ghidra_builtins().get("currentProgram") or _prog
                if prog:
                    go_to_address_in_ghidra(prog, addr_str)

            class _GoToHyperlinkListener(object):
                def hyperlinkUpdate(self, event):
                    try:
                        from javax.swing.event import HyperlinkEvent
                        if event.getEventType() != HyperlinkEvent.EventType.ACTIVATED:
                            return
                        url = event.getURL()
                        url_str = url.toString() if url else (event.getDescription() or "")
                        if not url_str or ("ghidra.goto" not in url_str and "ghidra:goTo" not in url_str):
                            return
                        addr_str = url_str.split("/")[-1].split(":")[-1].strip()
                        if addr_str:
                            _goto_addr(addr_str)
                    except Exception:
                        pass

            result_area.addHyperlinkListener(_GoToHyperlinkListener())
        except Exception:
            pass

        try:
            import re as _re_go

            def _on_result_click(event):
                try:
                    if event.getClickCount() != 1:
                        return
                    pos = result_area.viewToModel(event.getPoint())
                    doc = result_area.getDocument()
                    length = doc.getLength()
                    if pos < 0 or pos >= length:
                        return
                    text = doc.getText(0, length)
                    start = pos
                    while start > 0 and not text[start - 1].isspace():
                        start -= 1
                    end = pos
                    while end < length and not text[end].isspace():
                        end += 1
                    token = text[start:end].strip()
                    m = _re_go.search(r"0x[0-9a-fA-F]+", token)
                    if m:
                        _goto_addr(m.group(0))
                except Exception:
                    pass

            class _GoToMouseListener(object):
                def mouseClicked(self, e):
                    _on_result_click(e)
                def mousePressed(self, e): pass
                def mouseReleased(self, e): pass
                def mouseEntered(self, e): pass
                def mouseExited(self, e): pass

            result_area.addMouseListener(_GoToMouseListener())
        except Exception:
            pass

        def make_done_callback(area, tool_name):
            # Capture tool_name by value so closure always sees the correct tool (avoids wrong branch when run from thread)
            _t = tool_name

            def done_callback(payload):
                def update():
                    is_html = isinstance(payload, tuple) and len(payload) == 2 and payload[1] is True
                    content = payload[0] if isinstance(payload, tuple) else payload
                    # Explain Function: result ONLY in new window; tab shows status only (never full content)
                    if _t == "Explain Function":
                        try:
                            from AskJOE.gui_utils import show_result_in_window
                            show_result_in_window(content, "AskJOE – Explain Function", is_html=is_html)
                        except Exception:
                            pass
                        area.setContentType("text/html")
                        area.setText(
                            "<p style='color:#1565c0;'>Finished. Result opened in <b>new window</b>.</p>"
                            "<p style='color:#555;'>Check the popup window for the full explanation.</p>"
                        )
                        area.setCaretPosition(0)
                        try:
                            tools_status.setText("Finished Explain Function. Result opened in new window.")
                        except Exception:
                            pass
                    elif _t in ("Func Simplifier", "Threat Intel"):
                        # Result only in new window; tab shows status only
                        try:
                            from AskJOE.gui_utils import show_result_in_window
                            show_result_in_window(content, "AskJOE – " + _t, is_html=is_html)
                        except Exception:
                            pass
                        area.setContentType("text/html")
                        area.setText(
                            "<p style='color:#1565c0;'>Finished. Result opened in <b>new window</b>.</p>"
                            "<p style='color:#555; margin-top:8px;'>Only status is shown here; full output is in the new window.</p>"
                        )
                        area.setCaretPosition(0)
                        try:
                            tools_status.setText("Finished {}. Result opened in new window.".format(_t))
                        except Exception:
                            pass
                    else:
                        if is_html:
                            _set_pane_html_via_file(area, content)
                        else:
                            area.setContentType("text/plain")
                            area.setText(content)
                        area.setCaretPosition(0)
                        try:
                            tools_status.setText("Finished {}. Review results above.".format(_t))
                        except Exception:
                            pass
                if EventQueue.isDispatchThread():
                    update()
                else:
                    EventQueue.invokeLater(update)
            return done_callback

        def make_run_handler(script_path, tool_name, area):
            def on_run():
                try:
                    _run_tool(script_path, tool_name, area, name, _prog, _addr, frame, tools_status)
                except BaseException:
                    try:
                        JOptionPane.showMessageDialog(frame, "Run failed. Try running the tool from the Code Browser (cursor in a function) or reopen AskJOE.", "AskJOE", JOptionPane.WARNING_MESSAGE)
                    except Exception:
                        pass
                except:  # JPype/PyGhidra: catch any proxy or Java exception so button never crashes
                    try:
                        JOptionPane.showMessageDialog(frame, "Run failed. Try running the tool from the Code Browser (cursor in a function) or reopen AskJOE.", "AskJOE", JOptionPane.WARNING_MESSAGE)
                    except Exception:
                        pass
            return on_run

        def _run_tool(script_path, tool_name, area, name, _prog, _addr, frame, tools_status):
            if not _prog:
                JOptionPane.showMessageDialog(frame, "Open a program first (File > Import).", "AskJOE", JOptionPane.WARNING_MESSAGE)
                return
            if not os.path.isfile(script_path):
                JOptionPane.showMessageDialog(frame, "Script not found: {}".format(script_path), "AskJOE", JOptionPane.ERROR_MESSAGE)
                return
            capture = []
            builtins = _get_ghidra_builtins()
            # Prefer Code Browser cursor so Explain/Rename run on the function at cursor
            _prog_out, _addr_out = _prog, _addr
            try:
                from AskJOE import explain_utils
                if hasattr(explain_utils, 'get_program_and_address_from_code_browser'):
                    _live_prog, _live_addr = explain_utils.get_program_and_address_from_code_browser()
                    if _live_prog is not None and _live_addr is not None:
                        _prog_out, _addr_out = _live_prog, _live_addr
            except Exception:
                pass
            except:  # PyGhidra/JPype: catch Java Throwable or PyExceptionProxy
                pass
            # For Explain Function, show which function is being analyzed (name or address)
            _func_label = None
            if name == "Explain Function" and _prog_out and _addr_out:
                try:
                    fm = _prog_out.getFunctionManager()
                    if fm:
                        func = fm.getFunctionContaining(_addr_out)
                        if func is not None:
                            _func_label = getattr(func, "getName", lambda: None)()
                            if _func_label is not None:
                                _func_label = str(_func_label)
                except Exception:
                    pass
                if _func_label is None:
                    try:
                        _func_label = str(_addr_out) if _addr_out else None
                    except Exception:
                        pass
            area.setContentType("text/html")
            if _func_label:
                area.setText("<p style='color:#1565c0;'>Running <b>{}</b> on <b>{}</b>...</p>".format(tool_name, _func_label))
                try:
                    tools_status.setText("Running {} on {}...".format(tool_name, _func_label))
                except Exception:
                    pass
            else:
                area.setText("<p style='color:#1565c0;'>Running <b>{}</b>...</p>".format(tool_name))
                try:
                    tools_status.setText("Running {} on the current program...".format(tool_name))
                except Exception:
                    pass
            builtins["currentProgram"] = _prog_out
            builtins["currentAddress"] = _addr_out
            _get_mon = builtins.get("getMonitor")
            if _get_mon and callable(_get_mon):
                try:
                    builtins["monitor"] = _get_mon()
                except Exception:
                    builtins["monitor"] = None
            else:
                builtins["monitor"] = None
            if builtins.get("monitor") is None:
                builtins["monitor"] = _dummy_monitor()
            if not builtins.get("getMonitor") or not callable(builtins.get("getMonitor")):
                builtins["getMonitor"] = _dummy_monitor
            # Create callback here with current tool name so thread always gets the right one (closure fix)
            _done_cb = make_done_callback(area, name)
            threading.Thread(target=lambda _s=script_path, _c=capture, _cb=_done_cb, _b=builtins: _run_script(_s, _c, _cb, _b), name="AskJOE-{}".format(tool_name[:20]), daemon=True).start()

        run_btn.addActionListener(lambda e, h=make_run_handler(path, name, result_area): h())

        def clear_result(pane, status_label):
            def do_clear():
                try:
                    pane.setContentType("text/html")
                    pane.setText("<p style='color:#555;'>Output cleared. Click <b>Run</b> to execute again.</p>")
                    pane.setCaretPosition(0)
                except Exception:
                    pass
                try:
                    status_label.setText("Output cleared.")
                except Exception:
                    pass
            if EventQueue.isDispatchThread():
                do_clear()
            else:
                EventQueue.invokeLater(do_clear)

        _area = result_area
        _status = tools_status
        clear_btn.addActionListener(lambda e, _a=_area, _s=_status: clear_result(_a, _s))
        btn_row.add(run_btn)
        btn_row.add(clear_btn)
        tab_panel.add(btn_row, BorderLayout.NORTH)
        tab_panel.add(JScrollPane(result_area), BorderLayout.CENTER)
        tools_inner_tabs.addTab(name, tab_panel)
    tools_outer.add(tools_inner_tabs, BorderLayout.CENTER)
    tools_outer.add(tools_status, BorderLayout.SOUTH)
    tabs.addTab("Analysis", tools_outer)

    # ----- Settings tab (Phase 2) -----
    settings_panel = JPanel(BorderLayout())
    settings_panel.setBackground(JOES_PANEL_BG)
    settings_panel.setBorder(EmptyBorder(12, 12, 12, 12))
    settings_inner = JPanel()
    settings_inner.setLayout(BoxLayout(settings_inner, BoxLayout.Y_AXIS))
    settings_inner.setBackground(JOES_PANEL_BG)
    try:
        from AskJOE.ai_utils import read_config, write_config
        _prov = read_config("AI", "provider") or "claude"
        _model = read_config("AI", "claude_model") or "claude-sonnet-4-6"
        _openai_model = read_config("AI", "openai_model") or "gpt-3.5-turbo"
        _tri = read_config("AI", "triage_mode") or "deep_malware"
        _gui = read_config("AI", "use_gui") or "true"
        _openai_key = read_config("API_KEYS", "openai_api_key") or ""
        _claude_key = read_config("API_KEYS", "claude_api_key") or ""
    except Exception:
        _prov = "claude"
        _model = "claude-sonnet-4-6"
        _openai_model = "gpt-3.5-turbo"
        _tri = "deep_malware"
        _gui = "true"
        _openai_key = ""
        _claude_key = ""
    settings_fields = {}
    def add_setting(parent, label_text, key, default):
        row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        row.setBackground(JOES_PANEL_BG)
        lab = JLabel(label_text + ": ")
        lab.setPreferredSize(Dimension(140, 22))
        row.add(lab)
        if key == "provider":
            comp = JComboBox(["claude", "openai"])
            comp.setSelectedItem(_prov if _prov in ("claude", "openai") else "claude")
            comp.setPreferredSize(Dimension(180, 22))
        elif key == "model":
            # Model combo: contents depend on provider (set below via listener)
            _openai_models = [
                "gpt-4o",
                "gpt-4o-mini",
                "gpt-4-turbo",
                "gpt-4",
                "gpt-3.5-turbo",
            ]
            _claude_models = [
                "claude-sonnet-4-6",
                "claude-3-5-sonnet-20241022",
                "claude-3-5-haiku-20241022",
                "claude-3-opus-20240229",
                "claude-3-sonnet-20240229",
                "claude-3-haiku-20240307",
            ]
            _is_claude = (_prov == "claude")
            _model_list = _claude_models if _is_claude else _openai_models
            _model_val = (_model if _is_claude else _openai_model) or (_model_list[0] if _model_list else "")
            if _model_val and _model_val not in _model_list:
                _model_list = [_model_val] + list(_model_list)
            comp = JComboBox(_model_list)
            comp.setSelectedItem(_model_val)
            comp.setPreferredSize(Dimension(260, 22))
        elif key == "triage_mode":
            comp = JComboBox(["light", "deep_malware"])
            comp.setSelectedItem(_tri if _tri in ("light", "deep_malware") else "deep_malware")
            comp.setPreferredSize(Dimension(180, 22))
        elif key == "use_gui":
            comp = JCheckBox("", _gui.lower() in ("true", "1", "yes"))
            comp.setPreferredSize(Dimension(24, 22))
        elif key == "openai_api_key" or key == "claude_api_key":
            comp = JPasswordField(default, 24)
            comp.setEchoChar("*")
        else:
            comp = JTextField(default, 24)
        settings_fields[key] = comp
        row.add(comp)
        parent.add(row)
    add_setting(settings_inner, "AI Provider", "provider", _prov)
    add_setting(settings_inner, "Model", "model", _model)
    add_setting(settings_inner, "Triage mode", "triage_mode", _tri)
    add_setting(settings_inner, "Use GUI for results", "use_gui", _gui)
    add_setting(settings_inner, "OpenAI API key", "openai_api_key", _openai_key)
    add_setting(settings_inner, "Claude API key", "claude_api_key", _claude_key)
    # When provider changes, repopulate model dropdown with Claude or OpenAI models
    _openai_models_list = [
        "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo",
    ]
    _claude_models_list = [
        "claude-sonnet-4-6", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
        "claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307",
    ]

    def sync_model_to_provider():
        """Repopulate Model dropdown from current AI Provider selection."""
        try:
            prov_combo = settings_fields["provider"]
            prov = prov_combo.getSelectedItem()
            prov = str(prov).strip().lower() if prov is not None else "claude"
        except Exception:
            prov = "claude"
        model_combo = settings_fields["model"]
        model_combo.removeAllItems()
        if prov == "openai":
            lst = list(_openai_models_list)
            cur = (_openai_model or "gpt-3.5-turbo").strip()
            if cur not in lst:
                lst.insert(0, cur)
            for m in lst:
                model_combo.addItem(m)
            model_combo.setSelectedItem(cur)
        else:
            lst = list(_claude_models_list)
            cur = (_model or "claude-sonnet-4-6").strip()
            if cur not in lst:
                lst.insert(0, cur)
            for m in lst:
                model_combo.addItem(m)
            model_combo.setSelectedItem(cur)

    # Jython: use Python objects with the right method names (coerced to Java interfaces).
    class ProviderChangeListener(object):
        def itemStateChanged(self, ev):
            if ev.getStateChange() == ItemEvent.SELECTED:
                sync_model_to_provider()

    class ProviderActionListener(object):
        def actionPerformed(self, ev):
            sync_model_to_provider()

    class ProviderFocusListener(object):
        def focusLost(self, ev):
            sync_model_to_provider()
        def focusGained(self, ev):
            pass

    try:
        settings_fields["provider"].addItemListener(ProviderChangeListener())
        settings_fields["provider"].addActionListener(ProviderActionListener())
        settings_fields["provider"].addFocusListener(ProviderFocusListener())
    except Exception:
        pass
    # Ensure model list matches current provider on first show
    sync_model_to_provider()
    refresh_models_btn = JButton("Refresh models")
    refresh_models_btn.setToolTipText("Update the Model list to match the selected AI Provider (click after changing provider)")
    refresh_models_btn.setBackground(JOES_BTN_BG)
    refresh_models_btn.setForeground(JOES_BTN_FG)
    refresh_models_btn.setOpaque(True)
    refresh_models_btn.setContentAreaFilled(True)
    refresh_models_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
    refresh_models_row.setBackground(JOES_PANEL_BG)
    _spacer = JLabel(" ")
    _spacer.setPreferredSize(Dimension(140, 22))
    refresh_models_row.add(_spacer)
    refresh_models_row.add(refresh_models_btn)
    settings_inner.add(refresh_models_row)
    refresh_models_btn.addActionListener(lambda e: sync_model_to_provider())
    settings_inner.add(Box.createVerticalStrut(12))
    save_btn = JButton("Save to config.ini")
    save_btn.setBackground(JOES_BTN_BG)
    save_btn.setForeground(JOES_BTN_FG)
    save_btn.setOpaque(True)
    save_btn.setContentAreaFilled(True)
    settings_inner.add(save_btn)
    settings_scroll = JScrollPane(settings_inner)
    settings_panel.add(settings_scroll, BorderLayout.CENTER)
    settings_status = JLabel("Changes are written to AskJOE/config.ini.")
    settings_status.setForeground(JOES_HINT)
    settings_panel.add(settings_status, BorderLayout.SOUTH)

    def on_save_settings():
        try:
            from AskJOE.ai_utils import write_config
            _prov_val = settings_fields["provider"].getSelectedItem()
            _prov_val = str(_prov_val) if _prov_val is not None else "claude"
            write_config("AI", "provider", _prov_val)
            _model_comp = settings_fields["model"]
            _model_val = _model_comp.getSelectedItem() if hasattr(_model_comp, "getSelectedItem") else _model_comp.getText()
            _model_val = str(_model_val) if _model_val is not None else ""
            if _prov_val == "claude":
                write_config("AI", "claude_model", _model_val or "claude-sonnet-4-6")
            else:
                write_config("AI", "openai_model", _model_val or "gpt-3.5-turbo")
            _tri_val = settings_fields["triage_mode"].getSelectedItem()
            write_config("AI", "triage_mode", str(_tri_val) if _tri_val is not None else "deep_malware")
            write_config("AI", "use_gui", "true" if settings_fields["use_gui"].isSelected() else "false")
            _pk = settings_fields["openai_api_key"].getPassword()
            write_config("API_KEYS", "openai_api_key", "".join(_pk) if _pk else "")
            _ck = settings_fields["claude_api_key"].getPassword()
            write_config("API_KEYS", "claude_api_key", "".join(_ck) if _ck else "")
            settings_status.setText("Saved to config.ini. Restart tools for some options to take effect.")
        except Exception as ex:
            settings_status.setText("Save failed: {}".format(ex))

    save_btn.addActionListener(lambda e: on_save_settings())
    tabs.addTab("Config", settings_panel)

    main_content.add(tabs, BorderLayout.CENTER)
    frame.getContentPane().add(main_content)
    frame.getContentPane().setBackground(JOES_PANEL_BG)
    frame.setVisible(True)


def run():
    """Entry point when run as a Ghidra script."""
    def do_show():
        try:
            _show_launcher_gui()
        except Exception as e:
            try:
                println("[-] AskJOE launcher failed: {}".format(e))
            except Exception:
                print("[-] AskJOE launcher failed: {}".format(e))
            import traceback
            traceback.print_exc()
    try:
        from java.awt import EventQueue
        if EventQueue.isDispatchThread():
            do_show()
        else:
            EventQueue.invokeLater(do_show)
    except Exception:
        do_show()


try:
    run()
except Exception as e:
    print("AskJOE launcher error: {}".format(e))
