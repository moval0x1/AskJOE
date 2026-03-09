#!/usr/bin/env python

# 10_Rename_Helper.py – AskJOE Rename helper as a standalone tool
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @menupath Tools.SecurityJOES.Rename helper
# @toolbar JOES-black.png
# @runtime PyGhidra

"""
Standalone Rename helper for AskJOE.

This script opens a small GUI focused only on:
  1) Detecting the current function under the cursor (Listing/Decompiler).
  2) Asking the AI for better names for the function and its variables.
  3) Applying selected or all renames back into Ghidra.

It is also available from the AskJOE "Analysis" tab as a tool entry.
"""

import sys
import threading

try:
    from logging_utils import setup_logging
    _LOGGER, _LOG_PATH = setup_logging("rename_helper")
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
    Tries Code Browser tool first so Refresh matches the Listing/Decompiler cursor.
    """
    prog, addr = None, None
    try:
        from AskJOE.explain_utils import get_program_and_address_from_code_browser
        prog, addr = get_program_and_address_from_code_browser()
        if prog is not None and addr is not None:
            return prog, addr
    except Exception:
        pass
    except:  # PyGhidra/JPype: catch any proxy or Java exception
        pass
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


def _show_rename_helper():
    b = _get_ghidra_builtins()
    println = b.get("println", lambda msg: None)

    try:
        from java.awt import BorderLayout, Dimension, Color, Insets, FlowLayout, Font, EventQueue
        from javax.swing import (
            JFrame, JPanel, JScrollPane, JButton, JTable, JLabel, JTextArea,
            ListSelectionModel, JOptionPane
        )
        from javax.swing.border import EmptyBorder
        from javax.swing.table import DefaultTableModel
    except Exception as e:
        println("[-] Rename helper GUI requires Swing: {}".format(e))
        return

    # Basic styles – match main AskJOE light theme for consistency
    PANEL_BG = Color(0xF2, 0xF4, 0xF8)      # light gray panel background
    CONTENT_BG = Color(0xFF, 0xFF, 0xFF)    # white content areas
    BTN_BG = Color(0xEE, 0xEE, 0xEE)        # light gray buttons
    BTN_FG = Color(0x00, 0x00, 0x00)        # black button text
    HINT = Color(0x33, 0x33, 0x33)          # dark gray hint text

    frame = JFrame("AskJOE – Rename helper")
    try:
        from AskJOE.gui_utils import get_joes_icon
        _icon = get_joes_icon()
        if _icon is not None:
            frame.setIconImage(_icon)
    except Exception:
        pass
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    frame.setMinimumSize(Dimension(900, 400))

    root = JPanel(BorderLayout())
    root.setBackground(PANEL_BG)
    root.setBorder(EmptyBorder(12, 12, 12, 12))
    frame.add(root, BorderLayout.CENTER)

    # Button row
    btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
    btn_row.setBackground(PANEL_BG)

    refresh_btn = JButton("Refresh")
    refresh_btn.setToolTipText("Sync 'Current function' with the cursor in Ghidra")
    refresh_btn.setBackground(BTN_BG)
    refresh_btn.setForeground(BTN_FG)
    refresh_btn.setOpaque(True)
    refresh_btn.setContentAreaFilled(True)

    suggest_btn = JButton("Suggest variable & function names")
    suggest_btn.setToolTipText("Get AI rename suggestions for the current function (cursor must be inside the function)")
    suggest_btn.setBackground(BTN_BG)
    suggest_btn.setForeground(BTN_FG)
    suggest_btn.setOpaque(True)
    suggest_btn.setContentAreaFilled(True)

    apply_btn = JButton("Apply selected renames")
    apply_btn.setToolTipText("Apply the selected renames in this function")
    apply_btn.setBackground(BTN_BG)
    apply_btn.setForeground(BTN_FG)
    apply_btn.setOpaque(True)
    apply_btn.setContentAreaFilled(True)

    apply_all_btn = JButton("Apply all renames")
    apply_all_btn.setToolTipText("Apply all suggested renames in this function")
    apply_all_btn.setBackground(BTN_BG)
    apply_all_btn.setForeground(BTN_FG)
    apply_all_btn.setOpaque(True)
    apply_all_btn.setContentAreaFilled(True)

    btn_row.add(refresh_btn)
    btn_row.add(suggest_btn)
    btn_row.add(apply_btn)
    btn_row.add(apply_all_btn)

    # Current function label
    current_label = JLabel("Current function: —")
    current_label.setForeground(Color(0, 102, 153))
    current_label.setBorder(EmptyBorder(4, 0, 4, 0))
    try:
        current_label.setFont(current_label.getFont().deriveFont(Font.BOLD))
    except Exception:
        pass

    top = JPanel(BorderLayout())
    top.setBackground(PANEL_BG)
    top.add(btn_row, BorderLayout.NORTH)
    top.add(current_label, BorderLayout.CENTER)
    root.add(top, BorderLayout.NORTH)

    # Table: Current name | Suggested name | Kind | Confidence
    table_model = DefaultTableModel(["Current name", "Suggested name", "Kind", "Confidence (%)"], 0)
    table = JTable(table_model)
    table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    table.getTableHeader().setReorderingAllowed(False)
    table.setBackground(CONTENT_BG)

    root.add(JScrollPane(table), BorderLayout.CENTER)

    status = JLabel(
        "1) Place cursor in a function. 2) Click Refresh. 3) Suggest names. 4) Apply selected/all, then press F5 in the decompiler."
    )
    status.setForeground(HINT)
    status.setBorder(EmptyBorder(6, 0, 0, 0))
    root.add(status, BorderLayout.SOUTH)

    # Helpers
    def update_current_label():
        prog, addr = _get_live_prog_addr()
        if not prog or not addr:
            current_label.setText("Current function: — (open a program and place cursor in a function)")
            return
        try:
            fm = prog.getFunctionManager()
            func = fm.getFunctionContaining(addr)
            if func:
                current_label.setText("Current function: {}  at  {}".format(func.getName(), addr))
            else:
                current_label.setText("Current address: {}  (no function here)".format(addr))
        except Exception as ex:
            current_label.setText("Current function: — (error: {})".format(ex))

    def on_refresh(_e=None):
        prog, addr = _get_live_prog_addr()
        func_name = None
        if prog and addr:
            try:
                func = prog.getFunctionManager().getFunctionContaining(addr)
                func_name = func.getName() if func else None
            except Exception:
                pass
        if func_name:
            status.setText("Refreshed. Current function: {} at {}.".format(func_name, addr))
        else:
            status.setText("Refreshed. Current address: {} (no function here).".format(addr if addr else "—"))
        update_current_label()

    refresh_btn.addActionListener(on_refresh)

    def on_suggest(_e=None):
        prog, addr = _get_live_prog_addr()
        if not prog or not addr:
            status.setText("Open a program and place the cursor inside a function first.")
            return
        try:
            # make sure AskJOE package is importable
            # assume this script lives inside AskJOE/
            import os
            script_dir = os.path.dirname(__file__)
            repo_root = os.path.dirname(script_dir)
            if repo_root not in sys.path:
                sys.path.insert(0, repo_root)
            from AskJOE.explain_utils import get_current_function_decompiled
            code, func_name = get_current_function_decompiled(prog, addr)
            if not code:
                status.setText("No function at cursor. Place cursor inside a function.")
                return
        except Exception as ex:
            _log_exception("Error getting function for Rename helper", ex)
            status.setText("Error getting function. See latest log in AskJOE/logs for details.")
            return

        update_current_label()
        status.setText("Running AI rename suggestions for {}…".format(func_name or "current function"))
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

        def worker():
            try:
                from AskJOE.ai_utils import ask_open_ai, parse_open_ai_response
                resp = ask_open_ai(prompt)
                text = parse_open_ai_response(resp) if resp else ""
            except Exception as e:
                text = "Error: {}".format(e)

            def ui_update():
                table_model.setRowCount(0)
                if not text or "Error" in text:
                    status.setText(text or "No response from AI.")
                    return
                applied = 0
                for line in text.strip().split("\n"):
                    line = line.strip()
                    if "|" not in line or line.startswith("#"):
                        continue
                    parts = [p.strip() for p in line.split("|")[:4]]
                    if len(parts) >= 4:
                        _typ, _cur, _sug, _conf = parts[0], parts[1], parts[2], parts[3]
                        row = [_cur, _sug, _typ, _conf]
                        table_model.addRow(row)
                        applied += 1
                if applied:
                    status.setText(
                        "Done. Found {} suggestion(s). Select rows, then Apply selected or Apply all. Press F5 in the decompiler.".format(
                            applied
                        )
                    )
                else:
                    status.setText("Done. No parseable suggestions – AI may have used a different format.")

            if EventQueue.isDispatchThread():
                ui_update()
            else:
                EventQueue.invokeLater(ui_update)

        threading.Thread(target=worker, name="AskJOE-RenameSuggest", daemon=True).start()

    suggest_btn.addActionListener(on_suggest)

    def on_apply(selected_rows):
        if not selected_rows:
            status.setText("Select one or more rows to apply, or click Apply all.")
            return
        prog, addr = _get_live_prog_addr()
        if not prog or not addr:
            status.setText("Open a program and place the cursor in the function first.")
            return
        try:
            from ghidra.program.model.symbol import SourceType
            fm = prog.getFunctionManager()
            func = fm.getFunctionContaining(addr)
            if not func:
                status.setText("No function at cursor. Place cursor inside the function, then click Apply.")
                return
            applied = 0
            applied_funcs = 0
            applied_vars = 0

            def get_decompiler_symbol_map():
                try:
                    from ghidra.app.decompiler import DecompInterface
                    from ghidra.util.task import ConsoleTaskMonitor
                    from ghidra.program.model.pcode import HighFunctionDBUtil
                    ifc = DecompInterface()
                    ifc.openProgram(prog)
                    decomp = ifc.decompileFunction(func, 30, ConsoleTaskMonitor())
                    if decomp is None or not decomp.decompileCompleted():
                        return None
                    high_func = decomp.getHighFunction()
                    if high_func is None:
                        return None
                    local_map = high_func.getLocalSymbolMap()
                    if local_map is None:
                        return None
                    return local_map.getNameToSymbolMap()
                except Exception:
                    return None

            decomp_name_to_symbol = None
            tx_id = prog.startTransaction("AskJOE Apply renames (Rename helper)")
            try:
                for row_idx in selected_rows:
                    try:
                        current = str(table_model.getValueAt(row_idx, 0) or "").strip()
                        suggested = str(table_model.getValueAt(row_idx, 1) or "").strip()
                        typ = str(table_model.getValueAt(row_idx, 2) or "").strip().lower()
                    except Exception:
                        continue
                    if not suggested:
                        continue
                    if typ == "function":
                        func_name = str(func.getName()) if func.getName() else ""
                        if current == func_name:
                            try:
                                func.setName(suggested, SourceType.USER_DEFINED)
                                applied += 1
                                applied_funcs += 1
                            except Exception as e2:
                                _log_exception("Apply failed for function rename in Rename helper", e2)
                                status.setText("Apply failed for '{}'. See latest log in AskJOE/logs for details.".format(suggested))
                                return
                    elif typ == "variable":
                        renamed_here = False
                        try:
                            # Parameters
                            for p in func.getParameters():
                                try:
                                    if str(p.getName()) == current:
                                        p.setName(suggested, SourceType.USER_DEFINED)
                                        applied += 1
                                        applied_vars += 1
                                        renamed_here = True
                                except Exception:
                                    continue
                            # Locals
                            for lv in func.getLocalVariables():
                                try:
                                    if str(lv.getName()) == current:
                                        lv.setName(suggested, SourceType.USER_DEFINED)
                                        applied += 1
                                        applied_vars += 1
                                        renamed_here = True
                                except Exception:
                                    continue
                            # Stack names (local_1018 / uStack_102c etc.)
                            if not renamed_here:
                                try:
                                    frame = func.getStackFrame()
                                except Exception:
                                    frame = None
                                if frame is not None:
                                    name_norm = current.strip()
                                    if name_norm.startswith("!"):
                                        name_norm = name_norm[1:]
                                    prefixes = ("stack_", "local_", "uStack_", "ustack_", "lStack_", "lstack_")
                                    stack_off = None
                                    for pref in prefixes:
                                        if name_norm.startswith(pref):
                                            try:
                                                hex_part = name_norm.split("_", 1)[1]
                                                off = int(hex_part, 16)
                                                if frame.growsNegative():
                                                    off = -off
                                                stack_off = off
                                            except Exception:
                                                stack_off = None
                                            break
                                    if stack_off is not None:
                                        try:
                                            sv = frame.getVariableContaining(stack_off)
                                            if sv is not None:
                                                sv.setName(suggested, SourceType.USER_DEFINED)
                                                applied += 1
                                                applied_vars += 1
                                                renamed_here = True
                                        except Exception:
                                            pass
                            # Decompiler names (uVar1, puVar7, _Dst, etc.)
                            if not renamed_here:
                                try:
                                    from ghidra.program.model.pcode import HighFunctionDBUtil
                                    if decomp_name_to_symbol is None:
                                        decomp_name_to_symbol = get_decompiler_symbol_map()
                                    high_sym = decomp_name_to_symbol.get(current) if decomp_name_to_symbol is not None else None
                                    if high_sym is not None:
                                        HighFunctionDBUtil.updateDBVariable(high_sym, suggested, None, SourceType.USER_DEFINED)
                                        applied += 1
                                        applied_vars += 1
                                        renamed_here = True
                                except Exception:
                                    pass
                        except Exception as e2:
                            _log_exception("Apply failed for variable '{}' in Rename helper".format(current), e2)
                            status.setText("Apply failed for variable '{}'. See latest log in AskJOE/logs for details.".format(current))
                            return
                if applied:
                    if applied_funcs and applied_vars:
                        status.setText(
                            "Applied {} rename(s): {} function, {} variable(s). Refresh the decompiler (F5) to see the new names.".format(
                                applied, applied_funcs, applied_vars
                            )
                        )
                    elif applied_funcs:
                        status.setText(
                            "Applied {} function rename(s). Refresh the decompiler (F5) to see the new name.".format(
                                applied_funcs
                            )
                        )
                    else:
                        status.setText(
                            "Applied {} variable rename(s). Refresh the decompiler (F5) to see the new names.".format(
                                applied_vars
                            )
                        )
                else:
                    status.setText(
                        "No selected renames matched the current function or its variables. Ensure the cursor is in the right function.".format()
                    )
            finally:
                prog.endTransaction(tx_id, True)
        except Exception as ex:
            _log_exception("Apply failed in Rename helper", ex)
            status.setText("Apply failed. See latest log in AskJOE/logs for details.")

    def on_apply_selected(_e=None):
        rows = table.getSelectedRows()
        on_apply(rows)

    def on_apply_all(_e=None):
        try:
            row_count = table_model.getRowCount()
        except Exception:
            row_count = 0
        if row_count <= 0:
            status.setText("No suggestions to apply. Click Suggest names first.")
            return
        rows = list(range(row_count))
        on_apply(rows)

    apply_btn.addActionListener(on_apply_selected)
    apply_all_btn.addActionListener(on_apply_all)

    # Initial label
    EventQueue.invokeLater(update_current_label)

    frame.pack()
    frame.setLocationRelativeTo(None)
    frame.setVisible(True)


if __name__ == "__main__":
    _show_rename_helper()
