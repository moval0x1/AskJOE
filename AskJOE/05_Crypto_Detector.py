# AskJOE Crypto Detector - Detect cryptographic constants and algorithms
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT D
# @menupath Tools.SecurityJOES.Crypto Detector
# @runtime PyGhidra

import os
import sys
import datetime

# Repo root on path so "import AskJOE" resolves (launcher or standalone)
_ASKJOE_DIR = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_ASKJOE_DIR)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_warning, log_critical

# Import AskJOE data module for comprehensive crypto detection
from AskJOE import data

# Import Ghidra modules
from ghidra.program.model.symbol import SourceType

# Setup standardized logging
logger, log_file = setup_logging("crypto_detector")


def _python_bytes_to_java_byte_array(py_bytes):
    """Convert Python bytes to Java byte[] for Ghidra Memory.findBytes()."""
    from java.lang.reflect import Array
    from java.lang import Byte
    n = len(py_bytes)
    arr = Array.newInstance(Byte.TYPE, n)
    for i in range(n):
        b = py_bytes[i] if isinstance(py_bytes[i], int) else ord(py_bytes[i])
        Array.setByte(arr, i, (b - 256) if b > 127 else b)
    return arr


def _parse_constant_value(value):
    """Parse a constant from data (hex string '0x9E3779B9' or decimal) to int, 32-bit masked."""
    if value is None:
        return None
    s = str(value).strip().upper()
    try:
        if s.startswith("0X"):
            return int(s, 16) & 0xFFFFFFFF
        return int(s) & 0xFFFFFFFF
    except (ValueError, TypeError):
        return None

def detect_crypto_constants(operation):
    """Detect cryptographic constants in the program using AskJOE database"""
    try:
        log_info(logger, "Starting comprehensive cryptographic constant detection")
        println("[+] AskJOE Crypto Detection: {}".format(operation))
        
        symbolTable = currentProgram.getSymbolTable()
        total_detections = 0
        
        # Get crypto constants from AskJOE data module
        non_sparse_consts = data.non_sparse_consts
        sparse_consts = data.sparse_consts
        
        log_info(logger, "Analyzing {} non-sparse constants".format(len(non_sparse_consts)))
        println("[+] Analyzing {} non-sparse cryptographic constants...".format(len(non_sparse_consts)))
        
        # Process non-sparse constants (byte arrays)
        for const in non_sparse_consts:
            try:
                algorithm = const.get("algorithm", "Unknown")
                name = const.get("name", "Unknown")
                
                # Convert array to byte array if needed
                if "array" in const:
                    if const.get("size") == "B":  # Byte array
                        byte_array = bytes(const["array"])
                    elif const.get("size") == "L":  # Long array
                        byte_array = b"".join([x.to_bytes(4, 'little') for x in const["array"]])
                    else:
                        continue
                elif "byte_array" in const:
                    byte_array = const["byte_array"]
                else:
                    continue
                
                # Search for the constant in memory (mask = all 0xFF to match every byte).
                # Ghidra findBytes() requires Java byte[], not Python bytes; use ConsoleTaskMonitor (getMonitor() from launcher can be a non-TaskMonitor dummy).
                mask = b'\xff' * len(byte_array)
                java_bytes = _python_bytes_to_java_byte_array(byte_array)
                java_mask = _python_bytes_to_java_byte_array(mask)
                from ghidra.util.task import ConsoleTaskMonitor
                found = currentProgram.getMemory().findBytes(
                    currentProgram.getMinAddress(), java_bytes, java_mask, True, ConsoleTaskMonitor()
                )
                
                if found:
                    labelName = "aj_crypto_{}_{}_{}".format(algorithm.lower(), name.lower(), found)
                    log_info(logger, "Found crypto constant: {} {} at {}".format(algorithm, name, found))
                    println("[+] {} {} at 0x{} -> {}".format(algorithm, name, found, labelName))
                    
                    # Create symbol
                    symbolTable.createLabel(found, labelName, SourceType.USER_DEFINED)
                    total_detections += 1
                    
                    # Add comment
                    code_unit = currentProgram.getListing().getCodeUnitAt(found)
                    if code_unit:
                        comment = "Crypto constant: {} {} ({})".format(algorithm, name, const.get("description", "No description"))
                        code_unit.setComment(code_unit.PLATE_COMMENT, comment)
                        
            except Exception as e:
                log_warning(logger, "Error processing constant {} {}: {}".format(const.get('algorithm', 'unknown'), const.get('name', 'unknown'), e))
                continue

        log_info(logger, "Analyzing {} sparse constants".format(len(sparse_consts)))
        println("[+] Analyzing {} sparse cryptographic constants...".format(len(sparse_consts)))
        
        # Process sparse constants (32-bit immediates in instructions)
        # Check operand 0 and 1 (constants often in MOV reg, const or CMP, etc.)
        listing = currentProgram.getListing()
        instruction = listing.getInstructions(True)
        
        while instruction.hasNext():
            inst = instruction.next()
            # Collect scalar values from operands 0 and 1 (and 2) for comparison
            inst_values = set()
            for op_idx in (0, 1, 2):
                if op_idx >= inst.getNumOperands():
                    continue
                try:
                    scalar = inst.getScalar(op_idx)
                    if scalar is not None:
                        # 32-bit mask for our sparse constants
                        v = getattr(scalar, "getUnsignedValue", lambda: scalar.getValue())()
                        if v is not None:
                            inst_values.add(int(v) & 0xFFFFFFFF)
                except Exception:
                    pass
            
            if not inst_values:
                continue
                
            for const in sparse_consts:
                try:
                    algorithm = const.get("algorithm", "Unknown")
                    name = const.get("name", "Unknown")
                    if "array" not in const:
                        continue
                    for value in const["array"]:
                        const_val = _parse_constant_value(value)
                        if const_val is not None and const_val in inst_values:
                            labeladdr = inst.getAddress()
                            log_info(logger, "Found sparse constant: {} {} at {}".format(algorithm, name, labeladdr))
                            labelName = "aj_crypto_sparse_{}_{}_{}".format(algorithm.lower(), name.lower(), labeladdr)
                            symbolTable.createLabel(labeladdr, labelName, SourceType.USER_DEFINED)
                            println("[+] Sparse {} {} at 0x{} -> {}".format(algorithm, name, labeladdr, labelName))
                            total_detections += 1
                            code_unit = listing.getCodeUnitAt(labeladdr)
                            if code_unit:
                                comment = "Crypto constant: {} {} ({})".format(algorithm, name, const.get("description", "No description"))
                                code_unit.setComment(code_unit.PLATE_COMMENT, comment)
                            break  # one label per constant per instruction
                except Exception as e:
                    log_warning(logger, "Error processing sparse constant {} {}: {}".format(const.get('algorithm', 'unknown'), const.get('name', 'unknown'), e))
                    continue
                    
        # Summary
        log_info(logger, "Cryptographic constant detection completed. Found {} constants".format(total_detections))
        println("[+] Crypto detection completed successfully!")
        println("[+] Total cryptographic constants detected: {}".format(total_detections))
        
        if total_detections > 0:
            println("[+] Symbols created in Symbol Tree with 'aj_crypto_' prefix")
            println("[+] Check the Symbol Tree for detailed crypto analysis")
        else:
            println("[!] No cryptographic constants detected in this sample")
            println("[+] This may indicate:")
            println("    - No crypto algorithms used")
            println("    - Constants are obfuscated/encoded")
            println("    - Crypto functions are dynamically loaded")
        
    except Exception as e:
        error_msg = "Cryptographic constant detection failed: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting Crypto Detector script")
        monitor.setMessage("AskJOE Crypto Detector is running")
        
        detect_crypto_constants("Crypto Detection")
        
        log_info(logger, "Crypto Detector script completed successfully")
        println("Crypto Detector completed successfully!")
        
    except Exception as ex:
        error_msg = "Crypto Detector script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        println("[-] {}".format(error_msg))

try:
    run()
except Exception as ex:
    error_msg = "Critical error in Crypto Detector script: {}".format(str(ex))
    log_critical(logger, error_msg, exc_info=True)
    println("[-] {}".format(error_msg))
