# AskJOE Explain & Query helpers (IDAssist-style)
# Used by Explain Function tool and Query tab context macros.
# @category SecurityJOES

"""
Get decompiled code / disassembly for the current function or address.
All functions that touch Ghidra API should be called from the EDT (e.g. from button handlers).
"""

def get_current_function_decompiled(program, address):
    """
    Get decompiled C code for the function containing the given address.
    Must be called from Ghidra's main/EDT thread. Returns (code, function_name) or (None, None).
    """
    if not program or not address:
        return None, None
    try:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        fm = program.getFunctionManager()
        func = fm.getFunctionContaining(address)
        if not func:
            return None, None
        ifc = DecompInterface()
        ifc.openProgram(program)
        decomp = ifc.decompileFunction(func, 0, ConsoleTaskMonitor())
        if decomp and decomp.getDecompiledFunction():
            code = decomp.getDecompiledFunction().getC()
            return code, func.getName()
    except Exception:
        pass
    return None, None


def get_disassembly_around(program, address, num_lines=20):
    """
    Get disassembly lines around the given address.
    Must be called from Ghidra's main/EDT thread. Returns string or None.
    """
    if not program or not address:
        return None
    try:
        listing = program.getListing()
        cu = listing.getCodeUnitAt(address)
        if not cu:
            return None
        lines = []
        # Go back a few instructions
        addr = address
        for _ in range(num_lines // 2):
            cu = listing.getCodeUnitBefore(addr)
            if not cu:
                break
            addr = cu.getMinAddress()
        # Then forward
        addr = cu.getMinAddress() if cu else address
        for _ in range(num_lines):
            cu = listing.getCodeUnitAt(addr)
            if not cu:
                break
            lines.append("{}  {}".format(addr, cu.toString()))
            addr = cu.getMaxAddress().add(1)
        return "\n".join(lines) if lines else None
    except Exception:
        pass
    return None


EXPLAIN_PROMPT_TEMPLATE = """You are assisting with a detailed reverse-engineering analysis of a SINGLE C function.
Analyze ONLY the code shown below, as if you were a senior malware analyst working in Ghidra.

=== C FUNCTION CODE (function: {function_name}) ===
```c
{function_code}
```

PRIORITY: Lead with the 1–2 most security-relevant or surprising findings (e.g. anti-debug, C2, credential access, unusual APIs). What would a senior analyst notice first?

WHEN YOU REASON, STRICTLY SEPARATE:
A. FACTS: Directly observable from the code (APIs, constants, control flow). Quote names/values.
B. REASONED INTERPRETATIONS: What those facts most likely mean.
C. SPECULATIVE HYPOTHESES: Clearly marked as LOW CONFIDENCE.

Provide your answer in this structure:

1. FUNCTION SUMMARY
   - 2–3 sentences describing what this function ACTUALLY does based ONLY on the code.
   - If the role is unclear, say: "ROLE UNKNOWN FROM THIS FUNCTION ALONE".

2. TECHNICAL ANALYSIS
   2.1 API-CENTRIC VIEW
       - List EVERY Windows API or API-like call with call name, key parameters, and what resource it touches.
   2.2 DATA-FLOW VIEW
       - Where does data enter/leave? Note transformations (encryption, encoding, etc.).

3. MALWARE BEHAVIOR & ATTACK LIFECYCLE ROLE
   - Map to phases where possible (initial access, persistence, C2, credential theft, etc.).

4. MITRE ATT&CK MAPPING
   - List techniques as: TXXXX - Name - short justification. Only when supported by code facts.

5. RISK ASSESSMENT
   - Risk level (Benign / Low / Medium / High / Critical) and 3–5 supporting facts.

6. GAPS & FOLLOW-UP ACTIONS
   - What you cannot tell from this function alone; 3–5 next steps in Ghidra.

RULES: Base everything ONLY on the code shown. Prefer precise, technical language. Be concise but complete."""


def build_explain_prompt(function_code, function_name="unknown"):
    return EXPLAIN_PROMPT_TEMPLATE.format(
        function_name=function_name,
        function_code=function_code or "(no code)",
    )


def build_query_prompt(user_message, context_parts):
    """
    Build prompt for Query tab. context_parts is a list of strings (e.g. decompiled code, disassembly).
    """
    parts = []
    parts.append("You are helping a reverse engineer in Ghidra. Answer concisely and base your answer on the context below; cite specific names, addresses, or code when relevant.\n")
    if context_parts:
        parts.append("=== CONTEXT FROM LOADED BINARY (current function + disassembly from Ghidra) ===\n")
        for i, block in enumerate(context_parts, 1):
            if block:
                parts.append(block)
                parts.append("")
    parts.append("=== USER QUESTION ===")
    parts.append(user_message)
    return "\n".join(parts)


def resolve_query_macros(program, address, message):
    """
    Resolve #func and #addr in the user message. Returns (resolved_message, context_parts).
    Must be called from EDT. context_parts are strings to prepend to the prompt.

    MCP-like behavior: when a program and address are available, current function and
    disassembly are always included so the AI can answer questions about the binary
    (e.g. "is there any RC4?") without the user having to type #func/#addr.
    """
    context_parts = []
    resolved = message
    # Always add current function and disassembly when we have program + address
    # so queries like "find RC4 in this binary" get automatic context (MCP-like).
    user_asked_func = "#func" in message or "#function" in message.lower()
    user_asked_addr = "#addr" in message or "#address" in message.lower()
    inject_func = user_asked_func or not (user_asked_func or user_asked_addr)  # always inject if none specified
    inject_addr = user_asked_addr or not (user_asked_func or user_asked_addr)

    if inject_func:
        code, name = get_current_function_decompiled(program, address)
        if code:
            context_parts.append("[Current function: {}]\n```c\n{}\n```".format(name or "unknown", code))
            if user_asked_func:
                resolved = resolved.replace("#func", "[current function code above]").replace("#function", "[current function code above]")
        elif user_asked_func:
            resolved = resolved.replace("#func", "[could not decompile current function]").replace("#function", "[could not decompile current function]")
    if inject_addr:
        disasm = get_disassembly_around(program, address)
        if disasm:
            context_parts.append("[Disassembly around current address]\n```\n{}\n```".format(disasm))
            if user_asked_addr:
                resolved = resolved.replace("#addr", "[disassembly above]").replace("#address", "[disassembly above]")
        elif user_asked_addr:
            resolved = resolved.replace("#addr", "[no disassembly at current address]").replace("#address", "[no disassembly at current address]")
    return resolved, context_parts
