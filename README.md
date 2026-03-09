# AskJOE 3.0 – Advanced Malware Analysis Suite

[![GitHub stars](https://img.shields.io/github/stars/securityjoes/AskJOE)](https://github.com/securityjoes/AskJOE/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/securityjoes/AskJOE)](https://github.com/securityjoes/AskJOE/network)
[![License](https://img.shields.io/badge/License-GPL_v2-blue.svg)](LICENSE)

> **AI-powered malware analysis and threat intelligence for Ghidra**  
> A focused suite of helpers for malware analysis and reverse engineering: triage, capability detection, threat intel, string recovery, renaming, and reporting—all from one launcher with a consistent UI and clickable output.



## Table of contents

- [What is AskJOE 3.0?](#what-is-askjoe-30)
- [Main components](#main-components)
- [Tool overview](#tool-overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Using AskJOE](#using-askjoe)
- [Demo and screenshots](#demo-and-screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)



## What is AskJOE 3.0?

AskJOE 3.0 extends the original [AskJOE project](https://github.com/securityjoes/AskJOE) from a single AI-powered function analyzer into a full malware analysis suite. Built on **Ghidra** and **LLM integration** (OpenAI or Claude), it adds specialized modules for behaviour understanding, threat intelligence, and reverse-engineering workflows—all with a single launcher and shared configuration.


## Requirements

- **Ghidra** with Python scripting (PyGhidra; Ghidra 10+).
- **Python 3.x** (the interpreter used by Ghidra for scripts).
- **Network access** for AI-backed tools and threat-intel/sandbox APIs (if enabled).

Install Python dependencies from the project root:

```bash
pip install -r AskJOE/requirements.txt
```

## Installation

1. **Clone or copy the repo**  
![Script Directory](/imgs/ghidra-script-directory.png "Script Directory")

   Put `AskJOE.py` and the `AskJOE/` folder into your Ghidra **script directory** (e.g. `ghidra_scripts`), or any path already in Ghidra’s script paths.

2. **Configure API keys and options**  
   - Use `AskJOE/config.example.ini` as a template if provided, or edit `AskJOE/config.ini`.  
   - Set AI provider, model, and API keys (`[AI]`, `[API_KEYS]`).  
   - Set threat-intel keys as needed (`[VIRUSTOTAL]`, `[OTX]`, etc.).  
   - Adjust CAPA and other tool options if required.

3. **Run AskJOE in Ghidra** 

![Script Manager](/imgs/ghidra-script-manager.png "Ghidra Script Manager")
   - **Window > Script Manager** > add your script directory if needed.  
   - Find `AskJOE.py` (e.g. under **SecurityJOES**).  
   - Double-click to run; the AskJOE window opens.



## Main components

| Component | Description |
|-----------|-------------|
| **AskJOE launcher** (`AskJOE.py`) | Central entry point run from Ghidra’s Script Manager. Opens a tabbed window with **Analysis** (all tools) and **Config** (settings from `config.ini`). |

- Run **AskJOE.py** once to open the launcher.
- Use the **Analysis** tab to select and run any tool; results appear in the same window with styled HTML and clickable addresses.
- Use the **Config** tab to adjust API keys and options without editing `config.ini` by hand.



## Tool overview

Tools are grouped below by role. All support **clickable addresses** in the output where applicable (click to jump in the Listing/Decompiler).

### AI and explanation

| Tool | Goal |
|------|------|
| **AI Triage** | First-pass understanding: likely behaviour, IOCs, ATT&CK-style techniques. Structured HTML report; “light” or “deep” mode in `config.ini`. |
| **Explain Function** | Explains the function at the cursor using decompiler output. Click **Run**; the result opens in a new window. Tab shows status only. |
| **Ask AI** | Chat about the current binary. Presets for malware/vuln research; macros `#func`, `#addr`, `#strings`, `#imports`. Buttons to create **bookmarks** and **comments** from the latest answer. |

### Renaming and simplification

| Tool | Goal |
|------|------|
| **Rename Helper** | Rename functions and variables from one window. Uses live Code Browser cursor; **Refresh** then **Suggest**; apply selected or all. Handles params, locals, and decompiler-generated names. |
| **Function Simplifier** | Simplified view of the decompiled function; syntax-highlighted, IDE-like output. |

### Capability and threat intelligence

| Tool | Goal |
|------|------|
| **CAPA Analysis** | Runs Mandiant capa on the binary and imports results into Ghidra (symbols/comments). HTML report in AskJOE style. |
| **Threat Intelligence Analyzer** | Aggregates OSINT (VirusTotal, Hybrid Analysis, OTX, Malware Bazaar, Intezer, Any.Run, Triage, X-Force, etc.). Single HTML view; per-service status and rate-limit handling. |

### Detection and recovery

| Tool | Goal |
|------|------|
| **Crypto Detector** | Finds crypto-related code and constants (encryption/hashing candidates). |
| **XOR Searcher** | Identifies and decodes XOR-obfuscated data; filters noise; clickable addresses. Includes a short “How to read this” legend. |
| **Stack Strings Detector** | Recovers stack-constructed strings; table output tuned for malware workflows. |

### Export

| Tool | Goal |
|------|------|
| **Export Report** | Lightweight shareable report: merges AI Triage JSON, Threat Intel JSON, and latest CAPA log into a markdown-style HTML report; opens in a window and saves to disk. |

## Using AskJOE

### Opening the launcher

![AskJOE GUI](/imgs/askjoe-gui-analysis.png "AskJOE GUI")

- Run `AskJOE.py` from the Script Manager (or use the keybinding if set, e.g. **Ctrl+Shift+J**).  
- The window shows the **Analysis** tab (tool list + output) and **Config** tab.

![AskJOE GUI Config](/imgs/askjoe-gui-config.png "AskJOE GUI Config")

### Running any tool (general)

1. **File > Import** a binary in Ghidra and wait for analysis.  
2. In AskJOE **Analysis**, select a tool from the list.  
3. Click **Run**; results appear in the output pane (HTML, clickable addresses where applicable). For **Explain Function**, use **Refresh** first so the current function matches your cursor.  
4. Use **Clear output** to reset before another run.

### AI Triage

![AskJOE - AI Triage](/imgs/askjoe-ai-triage.png "AskJOE - AI Triage")

1. Open a binary in Ghidra and run initial analysis.  
2. In Analysis, select **AI Triage**.  
3. Click **Run**; the tool produces a first-pass report (behaviour, IOCs, ATT&CK-style techniques).  
4. Review the HTML output; addresses are clickable to jump in the Listing/Decompiler.  
5. Adjust "light" or "deep" mode in **Config** or `config.ini` if needed.


### Ask AI

![AskJOE - Ask AI](/imgs/askjoe-ask-ai.png "AskJOE - Ask AI")

1. Place the cursor in the function or address of interest.  
2. Open **Ask AI** from the Analysis tab.  
3. Optionally pick a preset (e.g. “Classify malware behaviour”, “Review interesting strings”).  
4. Use `#func`, `#addr`, `#strings`, `#imports` in your question to inject context.  
5. Click **Send**; use **Bookmark here** / **Comment here** to annotate Ghidra from the answer.


### Explain Function

![AskJOE - Explain Function](/imgs/askjoe-explain-function.png "AskJOE - Explain Function")

1. Place the cursor **inside** the function you want explained (in the Listing or Decompiler).  
2. In Analysis, select **Explain Function**.  
3. Click **Run**; the result opens in a new window (AI summary and step-by-step description). The tab shows status only.  
4. In the result window, click any address to jump to it in Ghidra.

### Function Simplifier

![AskJOE - Function Simplifier](/imgs/askjoe-func-simplifier.png "AskJOE - Function Simplifier")

1. Place the cursor inside the function you want to simplify.  
2. In Analysis, select **Func Simplifier**.  
3. Click **Run**; a simplified, syntax-highlighted view of the decompiled function is shown.  
4. Use the output to understand control flow and logic; status messages go to the Ghidra console.

### Rename Helper

![AskJOE - Rename Helper](/imgs/askjoe-rename-helper.png "AskJOE - Rename Helper")

1. Put the cursor inside the function you want to rename.  
2. In Analysis, open **Rename helper**.  
3. In the Rename Helper window: **Refresh** > **Suggest variable & function names**.  
4. Select rows and use **Apply selected renames** or **Apply all renames**.  
5. Names are applied to the function, parameters, and decompiler-visible locals.


### CAPA Analysis

![AskJOE - CAPA Analysis](/imgs/askjoe-capa-analysis.png "AskJOE - CAPA Analysis")

1. Open a binary in Ghidra; ensure **capa** is installed and configured (see `config.ini`).  
2. In Analysis, select **CAPA Analysis**.  
3. Click **Run**; capa runs on the binary and results are imported into Ghidra (symbols/comments).  
4. Review the HTML report in the output pane; click addresses to navigate.  
5. Inspect the Listing/Decompiler for capability markers added by the script.

### Threat Intelligence Analyzer

![AskJOE - Threat Intelligence](/imgs/askjoe-threat-intel.png "AskJOE - Threat Intelligence")

1. Configure API keys for desired services (VirusTotal, OTX, etc.) in **Config** or `config.ini`.  
2. Open a binary in Ghidra (file must be on disk for hashing).  
3. In Analysis, select **Threat Intel**.  
4. Click **Run**; the tool queries enabled services and aggregates results.  
5. Review the HTML report (families, campaigns, IOCs); per-service status is shown.

### Crypto Detector

![AskJOE - Crypto Detector](/imgs/askjoe-crypto-detector.png "AskJOE - Crypto Detector")

1. Open a binary in Ghidra and run analysis.  
2. In Analysis, select **Crypto Detector**.  
3. Click **Run**; the tool scans for crypto-related code and constants.  
4. Review the list of suspected encryption/hashing routines and addresses.  
5. Click addresses in the output to jump to candidates in the Listing/Decompiler.

### Stack Strings Detector

![AskJOE - Stack Strings](/imgs/askjoe-stack-strings.png "AskJOE - Stack Strings")

1. Open a binary in Ghidra and run analysis.  
2. In Analysis, select **Stack Strings**.  
3. Click **Run**; the tool recovers stack-constructed strings and shows them in a table.  
4. Review addresses and string content for malware-relevant data.  
5. Use clickable addresses to navigate to the corresponding code.

### XOR Searcher

![AskJOE - XOR Searcher](/imgs/askjoe-xor-search.png "AskJOE - XOR Searcher")

1. Open a binary in Ghidra and run analysis.  
2. In Analysis, select **XOR Search**.  
3. Click **Run**; the tool finds XOR patterns and decoded candidate strings.  
4. Read the "How to read this" legend in the output for loops and operands.  
5. Click addresses to inspect XOR routines in the Listing/Decompiler.

### Export Report

![AskJOE - Export Report](/imgs/askjoe-export-report.png "AskJOE - Export Report")

1. Run **AI Triage**, **Threat Intelligence**, and **CAPA** as needed (their outputs are used).  
2. In Analysis, select **Export report**.  
3. Click **Run**; the script builds a consolidated HTML report from the latest results.  
4. The report opens in a new window and is saved to disk.  
5. Share or attach the generated file for case notes, tickets, or reports.

---

## Demo and screenshots

*Add your demo video link and screenshots here. Suggested places:*

- **Main launcher** – AskJOE window with Analysis tab and tool list.
- **Explain Function** – “Current function” label, Refresh, and sample output.
- **Rename Helper** – Window with Refresh, Suggest, and the suggestions table.
- **Ask AI** – Chat window with presets and macro hints.
- **AI Triage / Threat Intel** – Example HTML report with clickable addresses.

Example:

```markdown
### Demo video

- [AskJOE 3.0 walkthrough](https://example.com/askjoe-demo) – Launch, AI Triage, Threat Intel, Rename Helper, Ask AI, Export Report.

### Screenshots

| Launcher | Explain Function | Rename Helper |
|----------|------------------|---------------|
| ![Launcher](screenshots/launcher.png) | ![Explain](screenshots/explain.png) | ![Rename](screenshots/rename.png) |
```

---

## Contributing

- Keep compatibility with supported Ghidra and PyGhidra versions.  
- Reuse existing patterns: `AskJOE/logging_utils.py`, error handling, status messages, and HTML/CSS output.  
- Update `ROADMAP.md` and `README.md` when adding tools or changing behaviour.

Pull requests and issues are welcome.

---

## License

This project is licensed under the **GPL-2.0 License**. See [LICENSE](LICENSE) for details.

---

## Contact

- **Security Joes**: [https://securityjoes.com](https://securityjoes.com)  
- **GitHub**: use the repository issue tracker for bugs and feature requests.
