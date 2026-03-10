#!/usr/bin/env python

# 12_Export_Report.py – AskJOE consolidated report exporter
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @menupath Tools.SecurityJOES.Export Report
# @toolbar JOES-black.png
# @runtime PyGhidra

"""
Export a consolidated analysis report for the current binary.

The report attempts to combine:
  - AI Triage results (if AI Triage was run and exported JSON exists),
  - Threat Intelligence results (if Threat Intelligence Analyzer was run),
  - A CAPA summary based on the latest CAPA Analysis log (if present).

The output is:
  - Saved as an HTML file under AskJOE/logs,
  - Optionally shown in a Swing window with AskJOE's HTML styling.
"""

import os
import sys
import json
import glob
import hashlib
import datetime


def _get_repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(here)


def _get_log_dir():
    """
    Resolve the AskJOE logs directory similar to 01_AI_Triage_Analysis/export_triage_results.
    """
    base_dir = _get_repo_root()
    log_dir = "logs"
    try:
        # Try to read LOGGING.log_directory from config.ini if available
        import configparser

        cfg_path = os.path.join(base_dir, "AskJOE", "config.ini")
        if os.path.exists(cfg_path):
            cfg = configparser.ConfigParser()
            cfg.read(cfg_path)
            if cfg.has_section("LOGGING") and cfg.has_option("LOGGING", "log_directory"):
                val = cfg.get("LOGGING", "log_directory").strip()
                if val:
                    log_dir = val
    except Exception:
        pass

    if not os.path.isabs(log_dir):
        log_dir = os.path.join(base_dir, log_dir)
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


def _get_program_sha256():
    """
    Compute a SHA256 for the currentProgram's backing file, or derive a stable-ish ID.
    Mirrors the logic used in AI Triage / Threat Intelligence where possible.
    """
    try:
        prog = currentProgram
    except Exception:
        return "UNKNOWN"

    try:
        path = prog.getExecutablePath()
        # Normalize /C:/ style on Windows
        if (
            path
            and os.name == "nt"
            and isinstance(path, str)
            and path.startswith("/")
            and len(path) > 2
            and path[2] == ":"
        ):
            path = path[1:]
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        pass

    # Fallback: hash some properties
    try:
        entry = str(prog.getEntryPoint())
        max_addr = str(prog.getMaxAddress())
        lang = str(prog.getLanguage())
        data = (entry + max_addr + lang).encode("utf-8")
        return hashlib.sha256(data).hexdigest()[:16]
    except Exception:
        return "UNKNOWN"


def _load_json_if_exists(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _find_latest_capa_log(log_dir):
    """
    Return the path of the most recent CAPA Analysis log file, or None.
    """
    pattern = os.path.join(log_dir, "AskJOE_capa_analysis_*.log")
    files = glob.glob(pattern)
    if not files:
        return None
    files.sort(key=lambda p: os.path.getmtime(p))
    return files[-1]


def _build_report_markdown(sha256, triage_obj, threat_obj, capa_log_text):
    lines = []
    prog_name = None
    try:
        prog = currentProgram
        if prog:
            prog_name = prog.getName()
    except Exception:
        pass

    title = "AskJOE Report"
    if prog_name:
        title += " – {}".format(prog_name)

    lines.append("# {}".format(title))
    lines.append("")
    lines.append("- Generated: {}".format(datetime.datetime.now().isoformat(timespec="seconds")))
    lines.append("- SHA256: `{}`".format(sha256))
    lines.append("")

    # AI Triage
    lines.append("## AI Triage")
    if triage_obj and isinstance(triage_obj, dict):
        formatted = triage_obj.get("formatted_response") or ""
        if formatted:
            # Already human-readable, just embed
            lines.append("")
            lines.append(formatted.strip())
        else:
            lines.append("")
            lines.append("_No formatted triage response stored in JSON (run AI Triage again)._")
    else:
        lines.append("")
        lines.append("_No AI Triage export JSON found for this sample._")

    # Threat Intelligence
    lines.append("")
    lines.append("## Threat Intelligence")
    if threat_obj and isinstance(threat_obj, dict):
        # Show a summarized view: top-level keys
        lines.append("")
        lines.append("The following sources were recorded in the Threat Intelligence export:")
        lines.append("")
        for k in sorted(threat_obj.keys()):
            if k.lower() in ("hash", "sha256"):
                continue
            lines.append("- **{}**".format(k))
        lines.append("")
        lines.append("```json")
        try:
            lines.append(json.dumps(threat_obj, indent=2, default=str))
        except Exception:
            lines.append(str(threat_obj))
        lines.append("```")
    else:
        lines.append("")
        lines.append("_No Threat Intelligence export JSON found for this sample._")

    # CAPA summary
    lines.append("")
    lines.append("## CAPA Analysis (summary)")
    if capa_log_text:
        lines.append("")
        lines.append(
            "The latest CAPA Analysis log is embedded below for convenience. "
            "Run CAPA Analysis from the AskJOE Analysis tab for more detail."
        )
        lines.append("")
        lines.append("```")
        lines.append(capa_log_text.strip())
        lines.append("```")
    else:
        lines.append("")
        lines.append("_No CAPA Analysis log found in AskJOE logs._")

    return "\n".join(lines)


def run():
    sha256 = _get_program_sha256()
    log_dir = _get_log_dir()

    # Locate exports
    triage_json_path = os.path.join(log_dir, "ai_triage_{}.json".format(sha256))
    threat_json_path = os.path.join(log_dir, "threat_intel_{}.json".format(sha256))
    triage_obj = _load_json_if_exists(triage_json_path)
    threat_obj = _load_json_if_exists(threat_json_path)

    capa_log_path = _find_latest_capa_log(log_dir)
    capa_log_text = None
    if capa_log_path and os.path.exists(capa_log_path):
        try:
            with open(capa_log_path, "r", encoding="utf-8", errors="replace") as f:
                capa_log_text = f.read()
        except Exception:
            capa_log_text = None

    report_md = _build_report_markdown(sha256, triage_obj, threat_obj, capa_log_text)

    # Write HTML report to logs
    try:
        from AskJOE.gui_utils import markdown_like_to_html, _build_html_document, show_triage_results
    except Exception:
        markdown_like_to_html = None
        show_triage_results = None

    html_path = os.path.join(log_dir, "AskJOE_report_{}.html".format(sha256))
    if markdown_like_to_html:
        try:
            body_html = markdown_like_to_html(report_md)
            full_html = _build_html_document(body_html, title="AskJOE Report")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(full_html)
        except Exception:
            # Fallback to plain text if HTML generation fails
            try:
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(report_md)
            except Exception:
                pass
    else:
        try:
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(report_md)
        except Exception:
            pass

    # Show in GUI if possible
    if show_triage_results:
        try:
            show_triage_results(report_md, title="AskJOE – Consolidated Report")
        except Exception:
            pass

    # Also print path to console for quick access
    try:
        println("[AskJOE] Consolidated report written to: {}".format(html_path))
    except Exception:
        print("[AskJOE] Consolidated report written to: {}".format(html_path))


try:
    run()
except Exception as ex:
    try:
        println("[-] Export Report failed: {}".format(ex))
    except Exception:
        print("[-] Export Report failed: {}".format(ex))

