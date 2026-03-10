# AskJOE Explain Function - AI analysis of current function (Explain tab logic)
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT E
# @menupath Tools.SecurityJOES.Explain Function
# @runtime PyGhidra

"""
Explain the function at the current cursor: decompile, send to AI, print result.
Used by the Explain tab and also available as a tool in the Tools list.
Output is markdown-like text; the launcher renders it as HTML.
"""

import os
import sys

_ASKJOE_DIR = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_ASKJOE_DIR)
# Ensure this script's repo root is first so AskJOE.explain_utils and others are found
while _repo_root in sys.path:
    sys.path.remove(_repo_root)
sys.path.insert(0, _repo_root)

try:
    from AskJOE.logging_utils import setup_logging, log_info, log_error
except ImportError:
    def setup_logging(name):
        return None, None
    def log_info(lg, msg): pass
    def log_error(lg, msg): pass

logger, _ = setup_logging("explain_function")

try:
    from AskJOE.explain_utils import get_current_function_decompiled, build_explain_prompt
except ImportError:
    get_current_function_decompiled = None
    build_explain_prompt = None

try:
    from AskJOE.ai_utils import ask_open_ai, parse_open_ai_response
except ImportError:
    ask_open_ai = None
    parse_open_ai_response = None


def run():
    prog = None
    addr = None
    try:
        prog = currentProgram
        addr = currentAddress
    except NameError:
        prog = globals().get("currentProgram")
        addr = globals().get("currentAddress")

    if not prog or not addr:
        println("[-] No program or address.")
        println("Place the cursor **inside** the function you want to analyze, then run Explain.")
        return

    if not get_current_function_decompiled or not build_explain_prompt:
        println("[-] Explain utils not available. Ensure AskJOE.explain_utils is importable.")
        return

    if not ask_open_ai or not parse_open_ai_response:
        println("[-] AI utils not available. Ensure AskJOE.ai_utils is configured.")
        return

    try:
        code, name = get_current_function_decompiled(prog, addr)
    except Exception as e:
        log_error(logger, "Decompile failed: {}".format(e))
        println("[-] Decompile failed: {}".format(e))
        return

    if not code:
        println("[-] No function at current address (or decompilation failed).")
        println("Place the cursor **inside** the function you want to explain, then run Explain again.")
        return

    if monitor and hasattr(monitor, "setMessage"):
        try:
            monitor.setMessage("AskJOE Explain: analyzing {}...".format(name or "unknown"))
        except Exception:
            pass

    log_info(logger, "Explaining function: {}".format(name or "unknown"))
    prompt = build_explain_prompt(code, name)

    try:
        resp = ask_open_ai(prompt)
        text = parse_open_ai_response(resp) if resp else "No response from AI."
    except Exception as e:
        log_error(logger, "AI request failed: {}".format(e))
        text = "Error: {}".format(e)

    # Output for launcher to capture and render as HTML (cursor tip is shown in GUI before run only)
    println(text)


try:
    run()
except Exception as e:
    log_error(logger, "Explain Function failed: {}".format(e))
    println("[-] Explain Function failed: {}".format(e))
    raise
