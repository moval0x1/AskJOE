# AskJOE Function Simplifier - Simplify complex functions for better understanding
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT S
# @menupath Tools.SecurityJOES.Function Simplifier
# @runtime PyGhidra

import os
import sys
import datetime
import json

# Repo root on path so "import AskJOE" resolves (launcher or standalone)
_ASKJOE_DIR = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_ASKJOE_DIR)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_debug, log_warning

# Optional config helper (for log directory)
try:
    from AskJOE.ai_utils import read_config
except ImportError:
    read_config = None

# Import AskJOE AI utilities
try:
    from AskJOE.ai_utils import ask_open_ai, parse_open_ai_response
    from AskJOE.ghidra_utils import print_joe_answer
except ImportError:
    # Fallback if AskJOE modules not available
    ask_open_ai = None
    parse_open_ai_response = None
    print_joe_answer = None

# Import Ghidra modules at top level
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import CodeUnit
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

# Setup standardized logging
logger, log_file = setup_logging("function_simplifier")

# Use println from execution context (AskJOE panel when run from launcher, console when standalone)

def simplify_function(operation, address, decompiled_function):
    """Simplify complex function code by converting to Python with better names"""
    try:
        log_info(logger, "Starting function simplification and Python conversion")
        
        log_info(logger, "Getting decompiled function code")
        function_code = decompiled_function.getDecompiledFunction().getC()
        log_info(logger, "Function code length: {} characters".format(len(function_code)))
        
        log_info(logger, "Sending code to AI provider for Python conversion")
        
        # Check if AI helper functions are available
        if not ask_open_ai:
            error_msg = "AI utilities not available. Please ensure AskJOE modules are properly installed."
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return

        prompt = (
            "Convert the following SINGLE C function into clear, readable Python while preserving its behavior.\n\n"
            "=== C FUNCTION CODE ===\n"
            "```c\n"
            + function_code
            + "\n```\n\n"
            "GOALS:\n"
            "- Preserve control flow, error paths, and unusual edge cases.\n"
            "- Make the logic easy to understand for a reverse engineer.\n\n"
            "NAMING:\n"
            "- Suggest a more descriptive Python function name if possible.\n"
            "- Use descriptive variable names, but keep them close enough to the original to be traceable (e.g., hwnd_window instead of v1).\n\n"
            "SECURITY & MALWARE CONTEXT:\n"
            "- Do NOT remove or hide suspicious behavior (networking, file/registry changes, credential access, clipboard/keylogging,\n"
            "  process injection, anti-debug/anti-VM checks, encryption/obfuscation, etc.).\n"
            "- Add SHORT inline comments ONLY where the behavior is security-relevant (e.g., \"# writes config to startup registry key\").\n"
            "- Do NOT add generic comments for trivial control flow.\n"
            "- At the top of the function, add a one-line docstring: what the function does and its single most security-relevant aspect (if any), e.g. \"Parses PE header; used for anti-debug / self-inspection\".\n\n"
            "OUTPUT FORMAT:\n"
            "- Return ONLY a valid Python code block implementing the function and any minimal helpers it needs.\n"
            "- Do NOT include explanations outside of comments in the code.\n"
        )

        response = ask_open_ai(prompt)

        # Check if parse function is available
        if not parse_open_ai_response:
            error_msg = "AI parse function not available. Please ensure AskJOE modules are properly installed."
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return
            
        open_ai_response = parse_open_ai_response(response)
        log_info(logger, "Received AI response successfully")
        
        # Display Python code conversion results (markdown so AskJOE panel renders nicely)
        out_lines = ["## Function Simplifier – Python conversion", ""]
        code = (open_ai_response or "").strip()
        if code.startswith("```"):
            out_lines.append(code)
        else:
            out_lines.append("```python")
            out_lines.append(code)
            out_lines.append("```")
        println("\n".join(out_lines))

        # Export simplification result for external tooling
        try:
            export_function_simplification(address, function_code, open_ai_response)
        except Exception as export_error:
            log_warning(logger, "Failed to export function simplification: {}".format(export_error))
        
        # Create concise summary for Ghidra comment
        try:
            # Extract key points for summary
            summary_lines = []
            for line in open_ai_response.split('\n'):
                line = line.strip()
                if line.startswith('- ') and len(line) < 100:  # Key bullet points
                    summary_lines.append(line)
                elif line.startswith('FUNCTION OVERVIEW:') or line.startswith('SUSPICIOUS:'):
                    summary_lines.append(line)
            
            # Create clean summary
            if summary_lines:
                ghidra_summary = "SIMPLIFIED: " + summary_lines[0].replace('- ', '')[:50]
                if len(summary_lines) > 1:
                    ghidra_summary += " | " + summary_lines[1].replace('- ', '')[:30]
            else:
                ghidra_summary = "SIMPLIFIED: Function analysis completed"
            
            # Add summary to Ghidra
            if GHIDRA_AVAILABLE:
                code_unit = currentProgram.getListing().getCodeUnitAt(address)
                if code_unit:
                    code_unit.setComment(code_unit.PLATE_COMMENT, ghidra_summary)
                    log_info(logger, "Added Ghidra comment: {}".format(ghidra_summary))
        except Exception as e:
            log_debug(logger, "Could not set Ghidra comment: {}".format(e))
        
        # Try to use AskJOE integration if available
        try:
            from AskJOE.ghidra_utils import print_joe_answer
            print_joe_answer(operation, open_ai_response)
        except ImportError:
            pass  # Already displayed in console above
        
        log_info(logger, "Function simplification completed successfully")
        
    except Exception as e:
        log_error(logger, "Function simplification failed: {}".format(e))
        println("[-] Function simplification failed: {}".format(e))


def export_function_simplification(address, function_code, simplified_code):
    """Export function simplification input and output to JSON."""
    try:
        # Determine base log directory
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_dir = "logs"

        try:
            if read_config:
                cfg_dir = read_config("LOGGING", "log_directory")
                if cfg_dir:
                    log_dir = cfg_dir
        except Exception as cfg_error:
            log_debug(logger, "Could not read log_directory from config: {}".format(cfg_error))

        if not os.path.isabs(log_dir):
            log_dir = os.path.join(base_dir, log_dir)

        os.makedirs(log_dir, exist_ok=True)

        addr_str = str(address).replace(" ", "").replace(":", "_")
        json_path = os.path.join(log_dir, "function_simplifier_{}.json".format(addr_str))

        export_obj = {
            "address": str(address),
            "function_code": function_code,
            "simplified_python": simplified_code,
            "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(export_obj, f, indent=2, default=str)

        log_info(logger, "Function simplification exported to {}".format(json_path))

    except Exception as e:
        log_warning(logger, "Could not export function simplification: {}".format(e))

def main():
    """Main function for the Function Simplifier"""
    try:
        println("[+] Starting Function Simplifier...")
        log_info(logger, "Function Simplifier started")
        
        # Check if we're in Ghidra environment
        try:
            if not currentProgram:
                error_msg = "No program loaded - not in Ghidra environment"
                log_error(logger, error_msg)
                println("[-] {}".format(error_msg))
                return False
        except NameError:
            error_msg = "Not running in Ghidra environment - currentProgram not available"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return False
        
        # Get current address
        if not currentAddress:
            error_msg = "No address selected"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return False
        
        address = currentAddress
        log_info(logger, "Analyzing function at address: {}".format(address))
        
        # Get function at current address
        try:
            function_manager = currentProgram.getFunctionManager()
            function = function_manager.getFunctionContaining(address)
        except Exception as e:
            error_msg = "Error getting function manager: {}".format(e)
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return False
        
        if not function:
            error_msg = "No function found at address {}".format(address)
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return False
        
        log_info(logger, "Found function: {}".format(function.getName()))
        
        # Get decompiled function
        if not GHIDRA_AVAILABLE:
            error_msg = "Ghidra modules not available - cannot decompile function"
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return False
            
        try:
            # First, try to get the function's raw bytes as a fallback
            try:
                function_bytes = function.getBody().getMinAddress()
                log_info(logger, "Function body available at: {}".format(function_bytes))
            except Exception as e:
                log_debug(logger, "Could not get function body: {}".format(e))
            
            # Initialize decompiler with proper error handling
            decompiler = DecompInterface()
            
            # Set decompiler options for better compatibility
            try:
                from ghidra.app.decompiler import DecompileOptions
                options = DecompileOptions()
                # Set timeout and other options for better compatibility
                options.setMaxPayloadMBytes(50)
                decompiler.setOptions(options)
            except Exception as opt_error:
                log_debug(logger, "Could not set decompiler options: {}, using defaults".format(opt_error))
            
            log_info(logger, "Starting decompilation...")
            
            # Try multiple decompilation approaches
            decompiled_function = None
            decompilation_success = False
            
            # Method 1: Standard decompilation
            try:
                decompiled_function = decompiler.decompileFunction(function, 30, ConsoleTaskMonitor())
                if decompiled_function and decompiled_function.decompileCompleted():
                    decompilation_success = True
                    log_info(logger, "Standard decompilation successful")
                else:
                    error_msg = decompiled_function.getErrorMessage() if decompiled_function else "Unknown error"
                    log_warning(logger, "Standard decompilation failed: {}".format(error_msg))
            except Exception as e:
                log_warning(logger, "Standard decompilation failed: {}".format(e))
            
            # Method 2: Try with different timeout
            if not decompilation_success:
                try:
                    decompiled_function = decompiler.decompileFunction(function, 60, ConsoleTaskMonitor())
                    if decompiled_function and decompiled_function.decompileCompleted():
                        decompilation_success = True
                        log_info(logger, "Extended timeout decompilation successful")
                    else:
                        error_msg = decompiled_function.getErrorMessage() if decompiled_function else "Unknown error"
                        log_warning(logger, "Extended timeout decompilation failed: {}".format(error_msg))
                except Exception as e:
                    log_warning(logger, "Extended timeout decompilation failed: {}".format(e))
            
            # Method 3: Try with minimal options
            if not decompilation_success:
                try:
                    # Reset decompiler and try minimal approach
                    decompiler = DecompInterface()
                    decompiled_function = decompiler.decompileFunction(function, 0, ConsoleTaskMonitor())
                    if decompiled_function and decompiled_function.decompileCompleted():
                        decompilation_success = True
                        log_info(logger, "Minimal options decompilation successful")
                    else:
                        error_msg = decompiled_function.getErrorMessage() if decompiled_function else "Unknown error"
                        log_warning(logger, "Minimal options decompilation failed: {}".format(error_msg))
                except Exception as e:
                    log_warning(logger, "Minimal options decompilation failed: {}".format(e))
            
            # Method 4: Try with program opened first
            if not decompilation_success:
                try:
                    # Try opening the program first, then decompile
                    decompiler = DecompInterface()
                    decompiler.openProgram(currentProgram)
                    decompiled_function = decompiler.decompileFunction(function, 30, ConsoleTaskMonitor())
                    if decompiled_function and decompiled_function.decompileCompleted():
                        decompilation_success = True
                        log_info(logger, "Program-opened decompilation successful")
                    else:
                        error_msg = decompiled_function.getErrorMessage() if decompiled_function else "Unknown error"
                        log_warning(logger, "Program-opened decompilation failed: {}".format(error_msg))
                except Exception as e:
                    log_warning(logger, "Program-opened decompilation failed: {}".format(e))
            
            # Check final result
            if decompilation_success and decompiled_function:
                log_info(logger, "Decompilation successful, calling simplify_function...")
                simplify_function("Function Simplification", address, decompiled_function)
                return True
            else:
                # All decompilation methods failed
                error_msg = "All decompilation methods failed. This function cannot be analyzed."
                log_error(logger, error_msg)
                println("[-] {}".format(error_msg))
                println("[-] Try analyzing a different function or use the Function Analyzer")
                return False
                
        except Exception as e:
            error_msg = "Error during decompilation setup: {}".format(e)
            log_error(logger, error_msg)
            println("[-] {}".format(error_msg))
            return False
        
    except Exception as e:
        error_msg = "Function Simplifier failed: {}".format(e)
        log_error(logger, error_msg)
        println("[-] {}".format(error_msg))
        return False

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting Function Simplifier script")
        try:
            monitor = getMonitor()
            if monitor:
                monitor.setMessage("AskJOE Function Simplifier is running")
        except NameError:
            log_debug(logger, "getMonitor not available, continuing without progress monitoring")
        
        # Run main function and check result
        success = main()
        
        if success:
            log_info(logger, "Function Simplifier script completed successfully")
            println("Function Simplifier completed successfully!")
        else:
            log_error(logger, "Function Simplifier script failed or encountered errors")
            println("[-] Function Simplifier failed or encountered errors")
        
    except Exception as ex:
        error_msg = "Function Simplifier script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

if __name__ == "__main__":
    run()
