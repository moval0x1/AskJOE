#!/usr/bin/env python

# Internal helper for AskJOE launcher: run child scripts with injected
# Ghidra builtins and capture their output as HTML.
#
# This file is intentionally independent of GhidraScript so it can be
# imported both from AskJOE.py and from unit-style tests.

import os
import sys
import tempfile
import traceback


def _find_askjoe_repo_root(script_path, askjoe_repo_root=None):
    """
    Return directory that contains AskJOE/logging_utils.py, or None.
    This is a simplified copy of the logic previously in AskJOE.py,
    with an optional hint (askjoe_repo_root) from the launcher.
    """

    def _norm(p):
        try:
            return os.path.normpath(os.path.abspath(p or ""))
        except Exception:
            return p or ""

    try:
        _dir = os.path.dirname(_norm(script_path))
        if _dir:
            for _ in range(10):
                if not _dir or _dir == os.path.dirname(_dir):
                    break
                _check = os.path.join(_dir, "AskJOE", "logging_utils.py")
                if os.path.isfile(_check):
                    return _norm(_dir)
                _dir = os.path.dirname(_dir)
    except Exception:
        pass

    if askjoe_repo_root:
        _check = os.path.join(askjoe_repo_root, "AskJOE", "logging_utils.py")
        if os.path.isfile(_check):
            return _norm(askjoe_repo_root)

    for _p in list(sys.path):
        if not _p:
            continue
        try:
            _p = _norm(_p)
            if os.path.isfile(os.path.join(_p, "AskJOE", "logging_utils.py")):
                return _p
        except Exception:
            continue
    return None


def run_script(script_path, capture_list, result_callback, builtins, askjoe_repo_root=None):
    """
    Run a script file with injected Ghidra builtins; capture println output
    into capture_list and call result_callback((html_or_text, is_html)) when done.

    - builtins: dict of Ghidra builtins (currentProgram, println, getMonitor, etc.)
    - askjoe_repo_root: optional repo root hint from the launcher.
    """
    try:
        with open(script_path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        _opened_path = getattr(f, "name", script_path)
    except Exception as e:
        capture_list.append("[-] Could not read script: {}".format(e))
        result_callback(("\n".join(capture_list), False))
        return

    # Normalize paths (Windows etc.)
    _script_abs = os.path.normpath(os.path.abspath(_opened_path if _opened_path else script_path))
    _repo_root = _find_askjoe_repo_root(_script_abs, askjoe_repo_root)
    if not _repo_root:
        _repo_root = _find_askjoe_repo_root(script_path, askjoe_repo_root)

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

    # Scripts expect 'monitor' in globals (e.g. monitor.setMessage); never leave None.
    class _DummyMonitor(object):
        def setMessage(self, msg):  # pragma: no cover
            pass

        def isCancelled(self):
            return False

        def setProgress(self, v):
            pass

        def setMaximum(self, v):
            pass

    _get_mon = runner_globals.get("getMonitor")
    if _get_mon and callable(_get_mon):
        try:
            runner_globals["monitor"] = _get_mon()
        except Exception:
            runner_globals["monitor"] = None
    else:
        runner_globals["monitor"] = None
    if runner_globals.get("monitor") is None:
        runner_globals["monitor"] = _DummyMonitor()
    if runner_globals.get("getMonitor") is None or not callable(runner_globals.get("getMonitor")):
        runner_globals["getMonitor"] = _DummyMonitor

    # Derive repo root from script path so "import AskJOE.logging_utils" works.
    _injected_repo = _repo_root
    if not _injected_repo and _script_abs:
        _askjoe_dir = os.path.dirname(os.path.normpath(os.path.abspath(_script_abs)))
        if os.path.isfile(os.path.join(_askjoe_dir, "logging_utils.py")):
            _injected_repo = os.path.dirname(_askjoe_dir)

    _path_fix = ""
    if _injected_repo:
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
            "# Prime AskJOE submodules so script imports find them\n"
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
        capture_list.append(traceback.format_exc())

    # Build HTML in this thread; callback only sets content on EDT.
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

