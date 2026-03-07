# AskJOE – AI-assisted reverse engineering for Ghidra
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @menupath Tools.SecurityJOES.AskJOE
# @keybinding CTRL SHIFT J
# @toolbar JOES-black.png
# @runtime PyGhidra

"""
AskJOE brings AI-augmented analysis and automation to Ghidra in one place.

**Tools tab** – Run analysis and detectors on the current binary:
  • AI Triage – Light or deep AI triage with MITRE ATT&CK-style findings
  • CAPA Analysis – Malware capabilities via capa rules
  • Explain Function – AI explanation of the function at the cursor (place cursor inside the function first)
  • Threat Intel – Hash lookups and context (VirusTotal, etc.)
  • Func Simplifier – AI simplification of complex functions
  • Crypto Detector – Cryptographic constants and algorithms (RC4, AES, ChaCha20, etc.)
  • Stack Strings / XOR Search – Recover stack-based and XOR-obfuscated strings
  • Function Graph – Push call graph to Neo4j and view an interactive embedded graph

**Query tab** – Chat about the binary; use **#func** to inject current function code and **#addr** for disassembly around the cursor. Answers are tailored for reverse engineers.

Open a binary (File → Import) before using Explain, Query, or tools that need a program.
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
# Order: triage → analysis → detectors → export
TOOLS = [
    ("AI Triage", "01_AI_Triage_Analysis.py"),
    ("CAPA Analysis", "02_CAPA_Analysis.py"),
    ("Explain Function", "03_Explain_Function.py"),
    ("Threat Intel", "08_Threat_Intelligence_Analyzer.py"),
    ("Func Simplifier", "04_Function_Simplifier.py"),
    ("Crypto Detector", "05_Crypto_Detector.py"),
    ("Stack Strings", "06_Stack_Strings_Detector.py"),
    ("XOR Search", "07_XOR_Searcher.py"),
    ("Function Graph", "09_Function_Graph.py"),
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


def _find_askjoe_repo_root(script_path):
    """Return directory that contains AskJOE/logging_utils.py, or None."""
    def _norm(p):
        try:
            return os.path.normpath(os.path.abspath(p or ""))
        except Exception:
            return p or ""

    try:
        _dir = os.path.dirname(_norm(script_path))
        if not _dir:
            return None
        for _ in range(10):
            if not _dir or _dir == os.path.dirname(_dir):
                break
            _check = os.path.join(_dir, "AskJOE", "logging_utils.py")
            if os.path.isfile(_check):
                return _norm(_dir)
            _dir = os.path.dirname(_dir)
    except Exception:
        pass
    if _ASKJOE_REPO_ROOT:
        _check = os.path.join(_ASKJOE_REPO_ROOT, "AskJOE", "logging_utils.py")
        if os.path.isfile(_check):
            return _norm(_ASKJOE_REPO_ROOT)
    for _p in list(sys.path):
        if not _p:
            continue
        try:
            _p = _norm(_p)
            if os.path.isfile(os.path.join(_p, "AskJOE", "logging_utils.py")):
                return _p
        except Exception:
            pass
    return None


def _run_script(script_path, capture_list, result_callback, builtins=None):
    """Run a script file with injected Ghidra builtins; capture println and call result_callback(text) when done.
    builtins should be from _get_ghidra_builtins() called on the main/EDT thread (so getMonitor etc. are defined).
    """
    if builtins is None:
        builtins = _get_ghidra_builtins()
    try:
        with open(script_path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        # Use the path of the file we actually opened (f.name can differ from script_path on some setups)
        _opened_path = getattr(f, "name", script_path)
    except Exception as e:
        capture_list.append("[-] Could not read script: {}".format(e))
        result_callback(("\n".join(capture_list), False))
        return

    # Normalize paths (Windows etc.)
    _script_abs = os.path.normpath(os.path.abspath(_opened_path if _opened_path else script_path))
    _repo_root = _find_askjoe_repo_root(_script_abs)
    if not _repo_root:
        _repo_root = _find_askjoe_repo_root(script_path)
    # Fallback: path ends with AskJOE/xxx.py -> repo root = parent of AskJOE
    if not _repo_root:
        try:
            _parts = os.path.normpath(_script_abs).split(os.sep)
            if "AskJOE" in _parts:
                i = _parts.index("AskJOE")
                _askjoe = os.sep.join(_parts[: i + 1])
                if os.path.isfile(os.path.join(_askjoe, "logging_utils.py")):
                    _repo_root = os.sep.join(_parts[:i])
        except Exception:
            pass
    if not _repo_root and _ASKJOE_REPO_ROOT:
        if os.path.isfile(os.path.join(_ASKJOE_REPO_ROOT, "AskJOE", "logging_utils.py")):
            _repo_root = os.path.normpath(_ASKJOE_REPO_ROOT)
    if _repo_root:
        _repo_root = os.path.normpath(os.path.abspath(_repo_root))
    # Ensure repo root is first in sys.path for this process (thread may share sys.path)
    if _repo_root:
        try:
            while _repo_root in sys.path:
                sys.path.remove(_repo_root)
        except Exception:
            pass
        sys.path.insert(0, _repo_root)
        try:
            import AskJOE.logging_utils  # noqa: F401
        except ImportError:
            pass
    elif _ASKJOE_REPO_ROOT:
        _fallback = os.path.normpath(os.path.abspath(_ASKJOE_REPO_ROOT))
        if os.path.isfile(os.path.join(_fallback, "AskJOE", "logging_utils.py")) and _fallback not in sys.path:
            sys.path.insert(0, _fallback)
            try:
                import AskJOE.logging_utils  # noqa: F401
            except ImportError:
                pass

    real_println = builtins.get("println", lambda x: print(x))

    def capturing_println(msg=""):
        """Print to AskJOE result page only (not Ghidra console)."""
        try:
            capture_list.append(str(msg))
        except Exception:
            pass

    def console_print(msg=""):
        """Print to Ghidra console only (use for errors when run from AskJOE)."""
        try:
            real_println(msg)
        except Exception:
            print(msg)

    runner_globals = {
        "__builtins__": __builtins__,
        "__name__": "__main__",
        "__file__": _script_abs,
        "println": capturing_println,
        "console_print": console_print,
    }
    runner_globals.update(builtins)
    runner_globals["println"] = capturing_println
    runner_globals["console_print"] = console_print
    # Scripts expect 'monitor' in globals (e.g. monitor.setMessage); never leave None (use dummy)
    _get_mon = runner_globals.get("getMonitor")
    if _get_mon and callable(_get_mon):
        try:
            runner_globals["monitor"] = _get_mon()
        except Exception:
            runner_globals["monitor"] = None
    else:
        runner_globals["monitor"] = None
    if runner_globals.get("monitor") is None:
        runner_globals["monitor"] = _dummy_monitor()
    if runner_globals.get("getMonitor") is None or not callable(runner_globals.get("getMonitor")):
        runner_globals["getMonitor"] = _dummy_monitor

    # Derive repo root from script path so "import AskJOE.logging_utils" works. Prepend to code
    # so it runs before any script line (avoids Jython/thread sys.path quirks).
    _injected_repo = _repo_root or (os.path.normpath(os.path.abspath(_ASKJOE_REPO_ROOT)) if _ASKJOE_REPO_ROOT and os.path.isfile(os.path.join(_ASKJOE_REPO_ROOT, "AskJOE", "logging_utils.py")) else None)
    if not _injected_repo and _script_abs:
        _askjoe_dir = os.path.dirname(os.path.normpath(os.path.abspath(_script_abs)))
        if os.path.isfile(os.path.join(_askjoe_dir, "logging_utils.py")):
            _injected_repo = os.path.dirname(_askjoe_dir)
    _path_fix = ""
    if _injected_repo:
        # Force repo root first; remove AskJOE dir so the package is found under repo root only.
        _askjoe_dir = os.path.join(_injected_repo, "AskJOE")
        _path_fix = (
            "_askjoe_repo = %r\n"
            "_askjoe_dir = %r\n"
            "import sys\n"
            "while _askjoe_dir in sys.path:\n"
            "    sys.path.remove(_askjoe_dir)\n"
            "if _askjoe_repo not in sys.path:\n"
            "    sys.path.insert(0, _askjoe_repo)\n"
            "else:\n"
            "    sys.path.remove(_askjoe_repo)\n"
            "    sys.path.insert(0, _askjoe_repo)\n"
            "# Prime AskJOE submodules so script imports find them (fixes exec() import in Ghidra/PyGhidra)\n"
            "_submodules = ('logging_utils', 'ai_utils', 'explain_utils', 'gui_utils', 'ghidra_utils', 'data')\n"
            "import importlib.util\n"
            "import types\n"
            "if 'AskJOE' not in sys.modules:\n"
            "    _pkg = types.ModuleType('AskJOE')\n"
            "    _pkg.__path__ = [_askjoe_dir]\n"
            "    sys.modules['AskJOE'] = _pkg\n"
            "_os = __import__('os')\n"
            "for _sub in _submodules:\n"
            "    _full = 'AskJOE.' + _sub\n"
            "    if _full in sys.modules:\n"
            "        continue\n"
            "    try:\n"
            "        __import__(_full)\n"
            "    except Exception:\n"
            "        _fp = _os.path.join(_askjoe_dir, _sub + '.py')\n"
            "        if _os.path.isfile(_fp):\n"
            "            _spec = importlib.util.spec_from_file_location(_full, _fp)\n"
            "            if _spec and _spec.loader:\n"
            "                _mod = importlib.util.module_from_spec(_spec)\n"
            "                sys.modules[_full] = _mod\n"
            "                setattr(sys.modules['AskJOE'], _sub, _mod)\n"
            "                try:\n"
            "                    _spec.loader.exec_module(_mod)\n"
            "                except Exception:\n"
            "                    del sys.modules[_full]\n"
            "                    try:\n"
            "                        delattr(sys.modules['AskJOE'], _sub)\n"
            "                    except AttributeError:\n"
            "                        pass\n"
            "    if _full in sys.modules and not hasattr(sys.modules['AskJOE'], _sub):\n"
            "        setattr(sys.modules['AskJOE'], _sub, sys.modules[_full])\n"
            "\n"
        ) % (_injected_repo, _askjoe_dir)
    try:
        exec(_path_fix + code, runner_globals)
    except Exception as e:
        capture_list.append("[-] Script error: {}".format(e))
        import traceback
        capture_list.append(traceback.format_exc())
        # Diagnostic block so you can see why "AskJOE.logging_utils" or similar failed
        try:
            capture_list.append("")
            capture_list.append("--- AskJOE path diagnostic ---")
            capture_list.append("  script_path (arg)   : {}".format(repr(script_path)))
            capture_list.append("  _opened_path (f.name): {}".format(repr(_opened_path)))
            capture_list.append("  _script_abs         : {}".format(repr(_script_abs)))
            capture_list.append("  _repo_root (found)  : {}".format(repr(_repo_root)))
            capture_list.append("  _injected_repo (prepended to script): {}".format(repr(_injected_repo)))
            capture_list.append("  _ASKJOE_REPO_ROOT (launcher): {}".format(repr(_ASKJOE_REPO_ROOT)))
            if _injected_repo:
                _init_py = os.path.join(_injected_repo, "AskJOE", "__init__.py")
                _log_py = os.path.join(_injected_repo, "AskJOE", "logging_utils.py")
                capture_list.append("  AskJOE/__init__.py exists: {}".format(os.path.isfile(_init_py)))
                capture_list.append("  AskJOE/logging_utils.py exists: {}".format(os.path.isfile(_log_py)))
            capture_list.append("  sys.path (first 10):")
            for _i, _p in enumerate(list(sys.path)[:10]):
                capture_list.append("    [{}] {!r}".format(_i, _p))
            capture_list.append("--------------------------------")
        except Exception as _diag_ex:
            capture_list.append("  (diagnostic failed: {})".format(_diag_ex))

    # Build HTML in this thread (imports work here); callback only sets content on EDT
    text = "\n".join(capture_list)
    try:
        from AskJOE.gui_utils import (
            preprocess_ai_response,
            markdown_like_to_html,
            script_output_to_html,
            _build_html_document,
        )
        normalized = preprocess_ai_response(text)
        if "##" in normalized or "```" in normalized:
            body = markdown_like_to_html(normalized)
        else:
            body = script_output_to_html(text)
        html = _build_html_document(body, title="AskJOE")
        result_callback((html, True))
    except Exception:
        try:
            from AskJOE.gui_utils import script_output_to_html, _build_html_document
            body = script_output_to_html(text)
            html = _build_html_document(body, title="AskJOE")
            result_callback((html, True))
        except Exception:
            result_callback((text, False))


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
    """Show the AskJOE tabbed window (Tools | Explain | Query) with icon and improved UX."""
    try:
        from java.awt import EventQueue, BorderLayout, Dimension, Color, Insets, FlowLayout, Point
        from java.awt.event import MouseListener, MouseMotionListener, MouseWheelListener, ActionListener
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
    except Exception as e:
        println("[-] AskJOE GUI requires Swing: {}".format(e))
        return

    def _run_graph_layout(nodes, edges):
        """Force-directed layout: returns list of (x,y) for each node."""
        n = len(nodes)
        if n == 0:
            return []
        radius = 200.0
        node_xy = []
        for i in range(n):
            angle = 2 * math.pi * i / n
            node_xy.append((radius * math.cos(angle), radius * math.sin(angle)))
        for _ in range(60):
            dx = [0.0] * n
            dy = [0.0] * n
            for i in range(n):
                for j in range(n):
                    if i == j:
                        continue
                    xi, yi = node_xy[i]
                    xj, yj = node_xy[j]
                    dist = max(math.hypot(xj - xi, yj - yi), 1.0)
                    rep = 800.0 / (dist * dist)
                    dx[i] -= (xj - xi) / dist * rep
                    dy[i] -= (yj - yi) / dist * rep
            edge_set = set((e.get("from"), e.get("to")) for e in edges)
            id_to_idx = {nodes[i][0]: i for i in range(n)}
            for (a, b) in edge_set:
                if a not in id_to_idx or b not in id_to_idx:
                    continue
                i, j = id_to_idx[a], id_to_idx[b]
                xi, yi = node_xy[i]
                xj, yj = node_xy[j]
                dist = max(math.hypot(xj - xi, yj - yi), 1.0)
                att = dist * 0.02
                dx[i] += (xj - xi) / dist * att
                dy[i] += (yj - yi) / dist * att
                dx[j] -= (xj - xi) / dist * att
                dy[j] -= (yj - yi) / dist * att
            for i in range(n):
                x, y = node_xy[i]
                node_xy[i] = (x + dx[i] * 0.5, y + dy[i] * 0.5)
        return node_xy

    def _paint_graph_to_image(state, width, height):
        """Draw graph into a BufferedImage. state: nodes, edges, node_xy, pan_x, pan_y, scale, hover_idx."""
        from java.awt import BasicStroke, RenderingHints
        from java.awt.image import BufferedImage
        from java.awt import Color as AWTColor
        img = BufferedImage(max(1, width), max(1, height), BufferedImage.TYPE_INT_RGB)
        g2 = img.createGraphics()
        try:
            if hasattr(g2, "setRenderingHint"):
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.setColor(AWTColor(0x1e, 0x1e, 0x1e))
            g2.fillRect(0, 0, width, height)
            g2.translate(int(state["pan_x"]), int(state["pan_y"]))
            g2.scale(state["scale"], state["scale"])
            g2.setStroke(BasicStroke(0.8))
            g2.setColor(AWTColor(0x55, 0x99, 0xcc, 120))
            nodes = state["nodes"]
            edges = state["edges"]
            node_xy = state["node_xy"]
            id_to_idx = {nodes[i][0]: i for i in range(len(nodes))}
            for e in edges:
                a, b = e.get("from"), e.get("to")
                if a not in id_to_idx or b not in id_to_idx:
                    continue
                i, j = id_to_idx[a], id_to_idx[b]
                x1, y1 = node_xy[i]
                x2, y2 = node_xy[j]
                g2.drawLine(int(x1), int(y1), int(x2), int(y2))
            r = 8
            hover_idx = state["hover_idx"]
            for i in range(len(nodes)):
                x, y = node_xy[i]
                if i == hover_idx:
                    g2.setColor(AWTColor(0x42, 0xa5, 0xf5))
                else:
                    g2.setColor(AWTColor(0x42, 0x85, 0xf4))
                g2.fillOval(int(x - r), int(y - r), int(2 * r), int(2 * r))
                g2.setColor(AWTColor(0xbb, 0xbb, 0xbb))
                g2.drawOval(int(x - r), int(y - r), int(2 * r), int(2 * r))
        finally:
            g2.dispose()
        return img

    def _make_embedded_graph_panel(nodes_data, edges_data, title_str):
        """Build an interactive graph using JPanel + JLabel (no Java class extension)."""
        nodes_list = []
        for node in nodes_data:
            nid = node.get("id") or ""
            label = node.get("label") or nid
            title = node.get("title") or label
            nodes_list.append((nid, label, title, 0.0, 0.0))
        edges_list = edges_data or []
        node_xy = _run_graph_layout(nodes_list, edges_list)
        state = {
            "nodes": nodes_list,
            "edges": edges_list,
            "node_xy": node_xy,
            "pan_x": 0.0,
            "pan_y": 0.0,
            "scale": 1.0,
            "hover_idx": -1,
            "drag_start": None,
        }

        def _node_at(sx, sy):
            scale = state["scale"]
            pan_x = state["pan_x"]
            pan_y = state["pan_y"]
            for i in range(len(state["nodes"])):
                x, y = state["node_xy"][i]
                nx = pan_x + scale * x
                ny = pan_y + scale * y
                if math.hypot(sx - nx, sy - ny) <= scale * 10:
                    return i
            return -1

        # Container panel and label (no subclassing)
        graph_w, graph_h = 860, 520
        container = JPanel(BorderLayout())
        label = JLabel()
        label.setPreferredSize(Dimension(graph_w, graph_h))

        def refresh():
            w = label.getWidth()
            h = label.getHeight()
            if w <= 0 or h <= 0:
                w, h = graph_w, graph_h
            img = _paint_graph_to_image(state, w, h)
            label.setIcon(ImageIcon(img))

        # Implement Java listener interfaces (not classes) so addMouseListener accepts this object
        class _GraphListeners(MouseListener, MouseMotionListener, MouseWheelListener):
            def mousePressed(self, e):
                state["drag_start"] = (e.getX(), e.getY(), state["pan_x"], state["pan_y"])

            def mouseReleased(self, e):
                state["drag_start"] = None

            def mouseClicked(self, e):
                pass

            def mouseEntered(self, e):
                pass

            def mouseExited(self, e):
                pass

            def mouseDragged(self, e):
                if state["drag_start"] is None:
                    return
                x, y = e.getX(), e.getY()
                ox, oy, px, py = state["drag_start"]
                state["pan_x"] = px + (x - ox)
                state["pan_y"] = py + (y - oy)
                state["drag_start"] = (x, y, state["pan_x"], state["pan_y"])
                refresh()

            def mouseMoved(self, e):
                idx = _node_at(e.getX(), e.getY())
                if idx != state["hover_idx"]:
                    state["hover_idx"] = idx
                    tip = state["nodes"][idx][2] if idx >= 0 else None
                    label.setToolTipText(tip if tip else None)
                    refresh()

            def mouseWheelMoved(self, e):
                d = -e.getWheelRotation()
                state["scale"] = max(0.2, min(5.0, state["scale"] * (1.0 + d * 0.15)))
                refresh()

        listener = _GraphListeners()
        label.addMouseListener(listener)
        label.addMouseMotionListener(listener)
        label.addMouseWheelListener(listener)
        container.add(label, BorderLayout.CENTER)
        refresh()
        return container

    def _find_neo4j_html_path(script_dir):
        """Return path to the Neo4j graph HTML: from last_neo4j_graph_path.txt or latest logs/neo4j_graph_*.html."""
        path_file = os.path.join(script_dir, "last_neo4j_graph_path.txt")
        if os.path.isfile(path_file):
            try:
                with open(path_file, "r", encoding="utf-8") as f:
                    p = f.read().strip()
                if p and os.path.isfile(p):
                    return p
            except Exception:
                pass
        log_dir = os.path.join(script_dir, "logs")
        if os.path.isdir(log_dir):
            candidates = []
            for name in os.listdir(log_dir):
                if name.startswith("neo4j_graph_") and name.endswith(".html"):
                    path = os.path.join(log_dir, name)
                    if os.path.isfile(path):
                        candidates.append((os.path.getmtime(path), path))
            if candidates:
                candidates.sort(key=lambda x: -x[0])
                return candidates[0][1]
        return None

    def _open_graph_in_browser(parent_frame, script_dir):
        """Open the Neo4j graph HTML in the default browser (no Java subclass; full interactive vis-network)."""
        html_path = _find_neo4j_html_path(script_dir)
        if not html_path:
            JOptionPane.showMessageDialog(parent_frame, "No graph HTML found. Run Function Graph first (it writes to AskJOE/logs/).", "AskJOE", JOptionPane.INFORMATION_MESSAGE)
            return False
        try:
            from java.awt import Desktop
            from java.net import URI
            uri = URI.create("file:///" + html_path.replace("\\", "/").replace(" ", "%20"))
            Desktop.getDesktop().browse(uri)
            return True
        except Exception as ex:
            JOptionPane.showMessageDialog(parent_frame, "Could not open browser: {}".format(ex), "AskJOE", JOptionPane.ERROR_MESSAGE)
            return False

    def _show_embedded_graph(parent_frame, script_dir):
        # script_dir is the AskJOE folder (config.ini, last_neo4j_graph.json)
        json_path = os.path.join(script_dir, "last_neo4j_graph.json")
        if not os.path.isfile(json_path):
            JOptionPane.showMessageDialog(parent_frame, "No graph data yet. Run Function Graph first, then click Embed graph.", "AskJOE", JOptionPane.INFORMATION_MESSAGE)
            return
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            nodes_data = data.get("nodes") or []
            edges_data = data.get("edges") or []
            title_str = data.get("title") or "Function Graph"
        except Exception as ex:
            JOptionPane.showMessageDialog(parent_frame, "Could not load graph: {}".format(ex), "AskJOE", JOptionPane.ERROR_MESSAGE)
            return
        if not nodes_data:
            JOptionPane.showMessageDialog(parent_frame, "Graph has no nodes.", "AskJOE", JOptionPane.WARNING_MESSAGE)
            return
        try:
            panel = _make_embedded_graph_panel(nodes_data, edges_data, title_str)
        except Exception as ex:
            # Jython cannot extend Java classes; open the HTML from logs in the browser instead (full interactive graph)
            opened = _open_graph_in_browser(parent_frame, script_dir)
            if opened:
                JOptionPane.showMessageDialog(parent_frame,
                    "The in-window viewer is not available in this environment.\n\n"
                    "The interactive graph has been opened in your default browser instead.",
                    "AskJOE", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(parent_frame, "Could not build graph panel: {}".format(ex), "AskJOE", JOptionPane.ERROR_MESSAGE)
            return
        try:
            emb_frame = JFrame("AskJOE – Function Graph (embedded)")
            emb_frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
            emb_frame.setSize(900, 600)
            emb_frame.setLocationRelativeTo(parent_frame)
            emb_frame.getContentPane().add(panel, BorderLayout.CENTER)
            header = JLabel("  {}  |  {} nodes, {} edges  |  Pan: drag  •  Zoom: wheel  •  Hover: tooltip".format(
                title_str, len(nodes_data), len(edges_data)))
            header.setBackground(Color(0x25, 0x25, 0x26))
            header.setOpaque(True)
            header.setForeground(Color(0xee, 0xee, 0xee))
            emb_frame.getContentPane().add(header, BorderLayout.NORTH)
            emb_frame.setVisible(True)
        except Exception as ex:
            JOptionPane.showMessageDialog(parent_frame, "Could not show graph window: {}".format(ex), "AskJOE", JOptionPane.ERROR_MESSAGE)

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

    # Logo: use local JOES.png (script dir or AskJOE folder) — official logo can be placed there
    _icon_image = None
    for _ip in [
        os.path.join(_SCRIPT_DIR, "JOES.png"),
        os.path.join(_ASKJOE_DIR, "JOES.png"),
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
        if name == "Explain Function":
            result_area.setText(
                "<p style='color:#555;'>Click <b>Run</b> to execute this tool. Output will appear here with the same styling as the Explain tab.</p>"
                "<p style='color:#c62828; margin-top:10px;'><b>Tip:</b> Place the cursor <b>inside</b> the function you want to analyze (in the Listing or Decompiler), then click Run.</p>"
            )
        else:
            result_area.setText("<p style='color:#555;'>Click <b>Run</b> to execute this tool. Output will appear here with the same styling as the Explain tab.</p>")

        def make_done_callback(area, tool_name):
            def done_callback(payload):
                def update():
                    is_html = isinstance(payload, tuple) and len(payload) == 2 and payload[1] is True
                    content = payload[0] if isinstance(payload, tuple) else payload
                    if is_html:
                        _set_pane_html_via_file(area, content)
                    else:
                        area.setContentType("text/plain")
                        area.setText(content)
                    area.setCaretPosition(0)
                    # When Function Graph succeeds, open the embedded viewer (no browser)
                    if tool_name == "Function Graph" and content and "[+] Neo4j:" in content and "[+] Graph saved" in content:
                        try:
                            _show_embedded_graph(frame, _ASKJOE_DIR)
                        except Exception:
                            pass
                if EventQueue.isDispatchThread():
                    update()
                else:
                    EventQueue.invokeLater(update)
            return done_callback

        def make_run_handler(script_path, tool_name, area):
            def on_run():
                if not _prog:
                    JOptionPane.showMessageDialog(frame, "Open a program first (File → Import).", "AskJOE", JOptionPane.WARNING_MESSAGE)
                    return
                if not os.path.isfile(script_path):
                    JOptionPane.showMessageDialog(frame, "Script not found: {}".format(script_path), "AskJOE", JOptionPane.ERROR_MESSAGE)
                    return
                capture = []
                area.setContentType("text/html")
                area.setText("<p style='color:#1565c0;'>Running <b>{}</b>...</p>".format(tool_name))
                builtins = _get_ghidra_builtins()
                # Ensure scripts get currentProgram, currentAddress (captured at open) and monitor (never None)
                builtins["currentProgram"] = _prog
                builtins["currentAddress"] = _addr
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
                threading.Thread(target=lambda: _run_script(script_path, capture, make_done_callback(area, name), builtins), name="AskJOE-{}".format(tool_name[:20]), daemon=True).start()
            return on_run

        run_btn.addActionListener(lambda e, h=make_run_handler(path, name, result_area): h())
        def clear_result(area):
            area.setContentType("text/html")
            area.setText("<p style='color:#555;'>Output cleared. Click <b>Run</b> to execute again.</p>")
        clear_btn.addActionListener(lambda e, a=result_area: clear_result(a))
        btn_row.add(run_btn)
        btn_row.add(clear_btn)
        if name == "Function Graph":
            view_graph_btn = JButton("View graph")
            view_graph_btn.setToolTipText("Reopen the last generated function graph in your browser")
            view_graph_btn.setBackground(JOES_BTN_BG)
            view_graph_btn.setForeground(JOES_BTN_FG)
            view_graph_btn.setOpaque(True)
            view_graph_btn.setContentAreaFilled(True)
            view_graph_btn.setBorderPainted(True)
            def open_last_graph():
                html_path = _find_neo4j_html_path(_ASKJOE_DIR)
                if not html_path:
                    JOptionPane.showMessageDialog(frame, "No graph HTML found. Run Function Graph first (writes to AskJOE/logs/).", "AskJOE", JOptionPane.INFORMATION_MESSAGE)
                    return
                try:
                    from java.awt import Desktop
                    from java.net import URI
                    uri = URI.create("file:///" + html_path.replace("\\", "/").replace(" ", "%20"))
                    Desktop.getDesktop().browse(uri)
                except Exception as ex:
                    JOptionPane.showMessageDialog(frame, "Could not open graph: {}".format(ex), "AskJOE", JOptionPane.ERROR_MESSAGE)
            view_graph_btn.addActionListener(lambda e: open_last_graph())
            btn_row.add(view_graph_btn)
            embed_graph_btn = JButton("Embed graph")
            embed_graph_btn.setToolTipText("Show the last function graph here (pan, zoom, hover)")
            embed_graph_btn.setBackground(JOES_BTN_BG)
            embed_graph_btn.setForeground(JOES_BTN_FG)
            embed_graph_btn.setOpaque(True)
            embed_graph_btn.setContentAreaFilled(True)
            embed_graph_btn.setBorderPainted(True)
            embed_graph_btn.addActionListener(lambda e: _show_embedded_graph(frame, _ASKJOE_DIR))
            btn_row.add(embed_graph_btn)
        tab_panel.add(btn_row, BorderLayout.NORTH)
        tab_panel.add(JScrollPane(result_area), BorderLayout.CENTER)
        tools_inner_tabs.addTab(name, tab_panel)
    tools_outer.add(tools_inner_tabs, BorderLayout.CENTER)
    tabs.addTab("Tools", tools_outer)

    # ----- Query tab -----
    query_panel = JPanel(BorderLayout())
    query_panel.setBackground(JOES_PANEL_BG)
    query_panel.setBorder(EmptyBorder(12, 12, 12, 12))
    query_turns = []  # list of {"role": "You"|"AskJOE", "text": "..."}
    query_display = JEditorPane()
    query_display.setContentType("text/html")
    query_display.setEditable(False)
    query_display.setMargin(Insets(8, 8, 8, 8))
    query_display.setBackground(JOES_CONTENT_BG)
    try:
        from javax.swing.text.html import HTMLEditorKit
        query_display.setEditorKit(HTMLEditorKit())
    except Exception:
        pass
    query_placeholder = (
        "<p style='color:#555;font-size:12px;'>Ask about the binary. Current function and disassembly are included automatically.</p>"
    )
    query_display.setText(query_placeholder)
    query_panel.add(JScrollPane(query_display), BorderLayout.CENTER)
    query_bottom = JPanel(BorderLayout())
    query_bottom.setBackground(JOES_PANEL_BG)
    query_bottom.setBorder(EmptyBorder(10, 0, 0, 0))
    hint = JLabel("<html><span style='color:#333;'>Ask about the binary. Context (current function + disassembly) is included automatically. Use <b>#func</b> / <b>#addr</b> to reference explicitly.</span></html>")
    hint.setForeground(JOES_HINT)
    hint_wrap = JPanel(BorderLayout())
    hint_wrap.setBackground(JOES_HINT_BG)
    hint_wrap.setBorder(CompoundBorder(
        MatteBorder(0, 4, 0, 0, JOES_HINT_ACCENT),
        EmptyBorder(10, 14, 10, 14)
    ))
    hint_wrap.add(hint, BorderLayout.CENTER)
    query_bottom.add(hint_wrap, BorderLayout.NORTH)
    query_input = JTextArea(4, 50)
    query_input.setLineWrap(True)
    query_input.setWrapStyleWord(True)
    query_input.setMargin(Insets(6, 8, 6, 8))
    query_input.setToolTipText("Type your question (multiple lines OK). Current function + disassembly are auto-included. Click Send to submit.")
    query_input.setBackground(JOES_CONTENT_BG)
    query_input_scroll = JScrollPane(query_input)
    query_input_scroll.setPreferredSize(Dimension(480, 88))
    query_send = JButton("Send")
    query_send.setToolTipText("Send the question to the AI")
    query_send.setBackground(JOES_BTN_BG)
    query_send.setForeground(JOES_BTN_FG)
    query_send.setOpaque(True)
    query_send.setContentAreaFilled(True)
    query_send.setBorderPainted(True)
    query_row = JPanel(BorderLayout())
    query_row.setBackground(JOES_PANEL_BG)
    query_row.add(query_input_scroll, BorderLayout.CENTER)
    _btn_wrap = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
    _btn_wrap.setBackground(JOES_PANEL_BG)
    _btn_wrap.add(query_send)
    query_row.add(_btn_wrap, BorderLayout.EAST)
    query_bottom.add(query_row, BorderLayout.CENTER)
    query_panel.add(query_bottom, BorderLayout.SOUTH)

    def render_query_conversation():
        """Rebuild and set HTML for the query conversation from query_turns."""
        try:
            from AskJOE.gui_utils import build_query_conversation_html, _build_html_document
            body = build_query_conversation_html(query_turns)
            html = _build_html_document(body, title="AskJOE Query")
            _set_pane_html_via_file(query_display, html)
            query_display.setCaretPosition(query_display.getDocument().getLength())
        except Exception:
            # fallback: plain text
            lines = []
            for t in query_turns:
                lines.append("[{}] {}".format(t.get("role", ""), (t.get("text", "") or "").replace("\n", "\n  ")))
            query_display.setContentType("text/plain")
            query_display.setText("\n\n".join(lines))

    def on_query_send():
        msg = query_input.getText()
        if not msg or not msg.strip():
            return
        query_input.setText("")
        if not _prog or not _addr:
            query_turns.append({"role": "You", "text": msg})
            query_turns.append({"role": "AskJOE", "text": "Open a program and place the cursor first so context (current function + disassembly) can be included."})
            render_query_conversation()
            return
        try:
            if _ASKJOE_REPO_ROOT and _ASKJOE_REPO_ROOT not in sys.path:
                sys.path.insert(0, _ASKJOE_REPO_ROOT)
            from AskJOE.explain_utils import resolve_query_macros, build_query_prompt
            resolved, context_parts = resolve_query_macros(_prog, _addr, msg)
            full_prompt = build_query_prompt(resolved, context_parts)
        except Exception as ex:
            query_turns.append({"role": "You", "text": msg})
            query_turns.append({"role": "AskJOE", "text": "Error building context: {}".format(ex)})
            render_query_conversation()
            return
        query_turns.append({"role": "You", "text": msg})
        query_turns.append({"role": "AskJOE", "text": "Thinking..."})
        render_query_conversation()

        def do_query():
            try:
                from AskJOE.ai_utils import ask_open_ai, parse_open_ai_response
                resp = ask_open_ai(full_prompt)
                text = parse_open_ai_response(resp) if resp else "No response from AI."
            except Exception as e:
                text = "Error: {}".format(e)

            def update():
                if query_turns and query_turns[-1].get("text") == "Thinking...":
                    query_turns[-1] = {"role": "AskJOE", "text": text}
                else:
                    query_turns.append({"role": "AskJOE", "text": text})
                render_query_conversation()

            if EventQueue.isDispatchThread():
                update()
            else:
                EventQueue.invokeLater(update)

        threading.Thread(target=do_query, name="AskJOE-Query", daemon=True).start()

    query_send.addActionListener(lambda e: on_query_send())
    tabs.addTab("Query", query_panel)

    # ----- Actions tab (Phase 2: rename suggestions) -----
    actions_panel = JPanel(BorderLayout())
    actions_panel.setBackground(JOES_PANEL_BG)
    actions_panel.setBorder(EmptyBorder(12, 12, 12, 12))
    actions_btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
    actions_btn_row.setBackground(JOES_PANEL_BG)
    suggest_btn = JButton("Suggest renames")
    suggest_btn.setToolTipText("Get AI rename suggestions for the current function (place cursor inside the function)")
    suggest_btn.setBackground(JOES_BTN_BG)
    suggest_btn.setForeground(JOES_BTN_FG)
    suggest_btn.setOpaque(True)
    suggest_btn.setContentAreaFilled(True)
    apply_btn = JButton("Apply selected")
    apply_btn.setToolTipText("Apply selected renames in Ghidra (function name only for now)")
    apply_btn.setBackground(JOES_BTN_BG)
    apply_btn.setForeground(JOES_BTN_FG)
    apply_btn.setOpaque(True)
    apply_btn.setContentAreaFilled(True)
    actions_table_model = DefaultTableModel(["Type", "Current name", "Suggested name", "Confidence"], 0)
    actions_table = JTable(actions_table_model)
    actions_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    actions_table.getTableHeader().setReorderingAllowed(False)
    refresh_btn = JButton("Refresh")
    refresh_btn.setToolTipText("Update 'Current function' to match Ghidra cursor (click after selecting another function)")
    refresh_btn.setBackground(JOES_BTN_BG)
    refresh_btn.setForeground(JOES_BTN_FG)
    refresh_btn.setOpaque(True)
    refresh_btn.setContentAreaFilled(True)
    actions_btn_row.add(suggest_btn)
    actions_btn_row.add(apply_btn)
    actions_btn_row.add(refresh_btn)
    actions_current_label = JLabel("Current function: —")
    actions_current_label.setForeground(Color(0, 102, 153))
    actions_current_label.setBorder(EmptyBorder(4, 0, 4, 0))
    actions_top = JPanel(BorderLayout())
    actions_top.setBackground(JOES_PANEL_BG)
    actions_top.add(actions_btn_row, BorderLayout.NORTH)
    actions_top.add(actions_current_label, BorderLayout.CENTER)
    actions_panel.add(actions_top, BorderLayout.NORTH)
    actions_panel.add(JScrollPane(actions_table), BorderLayout.CENTER)
    actions_status = JLabel("Place cursor in a function, click Refresh to show it, then Suggest renames.")
    actions_status.setForeground(JOES_HINT)
    actions_panel.add(actions_status, BorderLayout.SOUTH)

    def update_actions_current_label():
        """Update the 'Current function' label from Ghidra cursor (call on EDT)."""
        try:
            prog = currentProgram
            addr = currentAddress
        except Exception:
            prog = _prog
            addr = _addr
        if not prog or not addr:
            actions_current_label.setText("Current function: — (open a program and place cursor in a function)")
            return
        try:
            fm = prog.getFunctionManager()
            func = fm.getFunctionContaining(addr)
            if func:
                actions_current_label.setText("Current function: {}  at  {}".format(func.getName(), addr))
            else:
                actions_current_label.setText("Current address: {}  (no function here)".format(addr))
        except Exception as ex:
            actions_current_label.setText("Current function: — (error: {})".format(ex))

    def on_refresh_actions():
        update_actions_current_label()
        actions_status.setText("Refreshed. Place cursor in a function, then Suggest renames or Apply selected.")

    # Timer: every 2 sec update current-function label so selecting another function in Ghidra shows in AskJOE
    actions_last_addr = [None]

    def on_actions_timer():
        try:
            addr = currentAddress
            if addr is not None and str(addr) != str(actions_last_addr[0]):
                actions_last_addr[0] = addr
                update_actions_current_label()
        except Exception:
            pass

    try:
        from javax.swing import Timer
        actions_timer = Timer(2000, None)
        actions_timer.setRepeats(True)

        class TimerListener(object):
            def actionPerformed(self, event):
                on_actions_timer()
        actions_timer.addActionListener(TimerListener())
        actions_timer.start()
    except Exception:
        pass

    # Show current function as soon as Actions tab is available
    EventQueue.invokeLater(update_actions_current_label)

    refresh_btn.addActionListener(lambda e: on_refresh_actions())

    def on_suggest_renames():
        # Use current program/address at click time so we suggest for the function at cursor
        try:
            _prog_now = currentProgram
            _addr_now = currentAddress
        except Exception:
            _prog_now = _prog
            _addr_now = _addr
        if not _prog_now or not _addr_now:
            actions_status.setText("Open a program and place the cursor inside a function first.")
            return
        try:
            if _ASKJOE_REPO_ROOT and _ASKJOE_REPO_ROOT not in sys.path:
                sys.path.insert(0, _ASKJOE_REPO_ROOT)
            from AskJOE.explain_utils import get_current_function_decompiled
            code, func_name = get_current_function_decompiled(_prog_now, _addr_now)
            if not code:
                actions_status.setText("No function at cursor. Place cursor inside a function.")
                return
        except Exception as ex:
            actions_status.setText("Error getting function: {}".format(ex))
            return
        update_actions_current_label()
        actions_status.setText("Asking AI for rename suggestions for {}...".format(func_name or "current function"))
        prompt = (
            "You are helping rename symbols in a decompiled C function from a binary.\n\n"
            "=== C FUNCTION ===\n```c\n{}\n```\n\n"
            "Suggest better names for the FUNCTION and its LOCAL VARIABLES. "
            "Reply with exactly one line per suggestion in this format:\n"
            "TYPE|current_name|suggested_name|confidence\n"
            "where TYPE is 'function' or 'variable', and confidence is 0-100. "
            "Example:\nfunction|FUN_00401000|parse_config|85\nvariable|local_8|buffer_size|90\n"
            "Output ONLY these lines, no other text."
        ).format(code)
        def do_suggest():
            try:
                from AskJOE.ai_utils import ask_open_ai, parse_open_ai_response
                resp = ask_open_ai(prompt)
                text = parse_open_ai_response(resp) if resp else ""
            except Exception as e:
                text = "Error: {}".format(e)
            def update():
                actions_table_model.setRowCount(0)
                if not text or "Error" in text:
                    actions_status.setText(text or "No response from AI.")
                    return
                applied = 0
                for line in text.strip().split("\n"):
                    line = line.strip()
                    if "|" not in line or line.startswith("#"):
                        continue
                    parts = [p.strip() for p in line.split("|")[:4]]
                    if len(parts) >= 4:
                        actions_table_model.addRow(parts)
                        applied += 1
                actions_status.setText("Found {} suggestion(s). Select rows and click Apply selected to rename in Ghidra.".format(applied) if applied else "No parseable suggestions. AI may have used a different format.")
            if EventQueue.isDispatchThread():
                update()
            else:
                EventQueue.invokeLater(update)
        threading.Thread(target=do_suggest, name="AskJOE-SuggestRenames", daemon=True).start()

    def on_apply_renames():
        rows = actions_table.getSelectedRows()
        if not rows:
            actions_status.setText("Select one or more rows to apply.")
            return
        # Use current program/address at click time (not at window open) so Apply uses the right function
        try:
            _prog_now = currentProgram
            _addr_now = currentAddress
        except Exception:
            _prog_now = _prog
            _addr_now = _addr
        if not _prog_now or not _addr_now:
            actions_status.setText("Open a program and place the cursor in the function first.")
            return
        try:
            from ghidra.program.model.symbol import SourceType
            fm = _prog_now.getFunctionManager()
            func = fm.getFunctionContaining(_addr_now)
            if not func:
                actions_status.setText("No function at cursor. Place cursor inside the function, then click Apply.")
                return
            applied = 0
            # Ghidra requires program modifications inside a transaction
            tx_id = _prog_now.startTransaction("AskJOE Apply renames")
            try:
                row_indices = list(rows) if hasattr(rows, "__iter__") and not isinstance(rows, (str, dict)) else [rows]
                for row_idx in row_indices:
                    try:
                        typ = str(actions_table_model.getValueAt(row_idx, 0) or "").strip().lower()
                        current = str(actions_table_model.getValueAt(row_idx, 1) or "").strip()
                        suggested = str(actions_table_model.getValueAt(row_idx, 2) or "").strip()
                    except Exception:
                        continue
                    if not suggested or typ != "function":
                        continue
                    func_name = str(func.getName()) if func.getName() else ""
                    if current == func_name:
                        try:
                            func.setName(suggested, SourceType.USER_DEFINED)
                            applied += 1
                        except Exception as e2:
                            actions_status.setText("Apply failed for '{}': {}".format(suggested, e2))
                            return
                actions_status.setText("Applied {} function rename(s). Refresh the decompiler (F5) to see the new name.".format(applied) if applied else "No selected function renames matched current function (at cursor). Select the row for '{}' and ensure cursor is in that function.".format(func.getName()))
            finally:
                _prog_now.endTransaction(tx_id, True)
        except Exception as ex:
            actions_status.setText("Apply failed: {}".format(ex))

    suggest_btn.addActionListener(lambda e: on_suggest_renames())
    apply_btn.addActionListener(lambda e: on_apply_renames())
    tabs.addTab("Actions", actions_panel)

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
    tabs.addTab("Settings", settings_panel)

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
