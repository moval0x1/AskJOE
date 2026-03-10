# AskJOE CAPA Analysis - Automated malware analysis using CAPA command-line tool
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT C
# @menupath Tools.SecurityJOES.CAPA Analysis
# @runtime PyGhidra

import os
import sys
import json
import configparser
import subprocess

# Repo root on path so "import AskJOE" resolves (launcher or standalone)
_ASKJOE_DIR = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_ASKJOE_DIR)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_debug, log_critical, log_warning

# Setup standardized logging
logger, log_file = setup_logging("capa_analysis")

def _cerr(msg):
    """Print errors to Ghidra console only (when run from AskJOE). Else use println."""
    g = globals()
    out = g.get("console_print") or g.get("println")
    if out:
        try:
            out(str(msg))
        except Exception:
            print(msg)
    else:
        print(msg)

def load_config():
    """Load configuration from config.ini"""
    try:
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
        
        if not config.read(config_path):
            log_error(logger, "Could not read config file: {}".format(config_path))
            return None
            
        return config
    except Exception as e:
        log_error(logger, "Error loading config: {}".format(e))
        return None

def download_capa_signatures():
    """Download and extract official CAPA rules to the default directory"""
    try:
        # Get CAPA rules URL from config
        config = load_config()
        if config and 'CAPA' in config and config.has_option('CAPA', 'capa_rules_url'):
            signatures_url = config.get('CAPA', 'capa_rules_url')
        else:
            error_msg = "CAPA rules URL not found in config.ini"
            log_error(logger, error_msg)
            _cerr("[-] {}".format(error_msg))
            return False
            
        log_info(logger, "Using official CAPA rules from: {}".format(signatures_url))
        
        default_signatures_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capa_signatures")
        temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_capa_signatures_download")
        
        # Create temporary directory
        os.makedirs(temp_dir, exist_ok=True)
        
        # Download signatures
        try:
            import urllib.request
            import zipfile
            import shutil
            
            # Download the signatures file
            signatures_file = os.path.join(temp_dir, "capa_signatures.zip")
            log_info(logger, "Downloading CAPA signatures from: {}".format(signatures_url))
            
            urllib.request.urlretrieve(signatures_url, signatures_file)
            
            # Extract signatures
            with zipfile.ZipFile(signatures_file, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find the extracted rules directory (official CAPA rules archive structure)
            extracted_dir = None
            for item in os.listdir(temp_dir):
                item_path = os.path.join(temp_dir, item)
                if os.path.isdir(item_path) and "capa-rules" in item.lower():
                    extracted_dir = item_path
                    break
            
            if extracted_dir:
                # Copy to final location
                if os.path.exists(default_signatures_dir):
                    shutil.rmtree(default_signatures_dir)
                shutil.copytree(extracted_dir, default_signatures_dir)
                
                # Verify we have .yml files (recursively)
                yml_files = []
                for root, dirs, files in os.walk(default_signatures_dir):
                    yml_files.extend([f for f in files if f.endswith('.yml')])
                    
                if yml_files:
                    log_info(logger, "Official CAPA rules downloaded and extracted successfully. Found {} .yml files".format(len(yml_files)))
                    println("[+] Official CAPA rules downloaded successfully")
                    return True
                else:
                    log_error(logger, "No .yml rule files found after extraction")
                    return False
            else:
                log_error(logger, "Could not find capa-rules directory in downloaded archive")
                return False
                
        except Exception as e:
            log_error(logger, "Error downloading/extracting signatures: {}".format(e))
            return False
        finally:
            # Clean up temporary directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                
    except Exception as e:
        log_error(logger, "Error in download_capa_signatures: {}".format(e))
        return False

def run_capa_analysis(operation):
    """Run CAPA analysis on the current program"""
    try:
        log_info(logger, "Starting CAPA analysis")
        println("[+] AskJOE CAPA Analysis: {}".format(operation))
        
        # Get current program path
        if not currentProgram:
            error_msg = "No program loaded"
            log_error(logger, error_msg)
            _cerr("[-] {}".format(error_msg))
            return
            
        program_path = currentProgram.getExecutablePath()
        # Normalize Windows path if Ghidra returns /C:/style
        if program_path and os.name == "nt" and isinstance(program_path, str) and program_path.startswith("/") and len(program_path) > 2 and program_path[2] == ":":
            program_path = program_path[1:]
        if not program_path:
            error_msg = "Could not get program executable path"
            log_error(logger, error_msg)
            _cerr("[-] {}".format(error_msg))
            return
            
        # Check if file exists
        if not os.path.exists(program_path):
            error_msg = "Program file not found at: {}".format(program_path)
            log_error(logger, error_msg)
            _cerr("[-] {}".format(error_msg))
            _cerr("[!] This may happen if the file was moved or deleted after loading")
            _cerr("[+] Try reloading the program in Ghidra")
            return
            
        log_info(logger, "Analyzing program: {}".format(program_path))

        # Resolve CAPA executable from config (default: "capa" on PATH)
        config = load_config()
        capa_exe = "capa"
        if config and config.has_section("CAPA") and config.has_option("CAPA", "capa_exe"):
            capa_exe = config.get("CAPA", "capa_exe", fallback="capa").strip() or "capa"

        # Check if CAPA is available
        try:
            result = subprocess.run([capa_exe, "--version"], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                error_msg = "CAPA command failed: {}".format(result.stderr)
                log_error(logger, error_msg)
                _cerr("[-] {}".format(error_msg))
                return
            log_info(logger, "CAPA version: {}".format(result.stdout.strip()))
        except (subprocess.CalledProcessError, FileNotFoundError):
            log_error(logger, "CAPA command not found. capa_exe=%s" % capa_exe)
            _cerr("[-] CAPA command not found.")
            _cerr("")
            _cerr("    Ghidra uses a different PATH than your terminal, so 'capa' may not be found.")
            _cerr("    If you already ran:  pip install capa")
            _cerr("    use the *full path* to capa in config.ini:")
            _cerr("")
            _cerr("    1. In a terminal (cmd or PowerShell), run:")
            if os.name == "nt":
                _cerr("       where capa")
            else:
                _cerr("       which capa")
            _cerr("    2. Copy the path (e.g. ...\\Python\\Scripts\\capa.exe) and in config.ini set:")
            _cerr("       [CAPA]")
            _cerr("       capa_exe = <that full path>")
            _cerr("")
            _cerr("    Or download the standalone from https://github.com/mandiant/capa/releases")
            _cerr("    and set capa_exe to its path.")
            _cerr("")
            return
        except subprocess.TimeoutExpired:
            error_msg = "CAPA version check timed out"
            log_error(logger, error_msg)
            _cerr("[-] {}".format(error_msg))
            return
        
        # Get CAPA signatures directory (official rules from capa-rules repo)
        signatures_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capa_signatures")
        
        # Force-update official rules before each run (or download if missing)
        update_rules = True
        try:
            config = load_config()
            if config and config.has_section("CAPA") and config.has_option("CAPA", "update_rules_before_run"):
                raw = config.get("CAPA", "update_rules_before_run", fallback="true").strip().lower()
                update_rules = raw in ("true", "1", "yes")
        except Exception:
            pass
        if update_rules:
            log_info(logger, "Updating CAPA rules from official repository...")
            println("[+] Updating CAPA rules...")
            if not download_capa_signatures():
                if not os.path.exists(signatures_dir):
                    error_msg = "Failed to download CAPA rules and no cached rules found"
                    log_error(logger, error_msg)
                    _cerr("[-] {}".format(error_msg))
                    return
                log_warning(logger, "Rules update failed; using cached rules")
                _cerr("[!] Update failed; using cached rules.")
        elif not os.path.exists(signatures_dir):
            log_info(logger, "CAPA rules not found, downloading...")
            println("[+] Downloading CAPA rules...")
            if not download_capa_signatures():
                error_msg = "Failed to download CAPA rules"
                log_error(logger, error_msg)
                _cerr("[-] {}".format(error_msg))
                return
        
        # Run CAPA analysis
        log_info(logger, "Running CAPA analysis...")
        println("[+] Running CAPA analysis...")
        
        # Use absolute paths to avoid any working directory issues
        abs_signatures_dir = os.path.abspath(signatures_dir)
        abs_program_path = os.path.abspath(program_path)
        
        log_info(logger, "Working directory: {}".format(os.getcwd()))
        log_info(logger, "Rules path (official): {}".format(abs_signatures_dir))
        log_info(logger, "Program path: {}".format(abs_program_path))
        
        # Run CAPA analysis using subprocess (fallback approach)
        log_info(logger, "Running CAPA analysis using subprocess...")
        println("[+] Running CAPA analysis using subprocess...")
        
        # Get verbose level from config
        try:
            config = configparser.ConfigParser()
            config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"))
            verbose_level = config.get('CAPA', 'capa_verbose_level', fallback='')
        except Exception as e:
            log_warning(logger, "Could not read verbose level from config: {}".format(e))
            verbose_level = ''
        
        # -r = rules (YAML). Use only official rules (capa_signatures) to avoid duplicate rule names and missing paths.
        cmd = [capa_exe, "-j"]
        if verbose_level:
            cmd.extend(verbose_level.split())
        cmd.extend(["-r", abs_signatures_dir, abs_program_path])
        
        log_info(logger, "CAPA command: {}".format(" ".join(cmd)))
        println("[+] CAPA command: {}".format(" ".join(cmd)))
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            error_msg = "CAPA analysis failed with return code: {}".format(result.returncode)
            log_error(logger, error_msg)
            _cerr("[-] {}".format(error_msg))
            
            if result.stderr:
                log_error(logger, "CAPA stderr: {}".format(result.stderr))
                _cerr("[-] Error details: {}".format(result.stderr))
            
            if result.stdout:
                log_error(logger, "CAPA stdout: {}".format(result.stdout))
                _cerr("[!] CAPA output: {}".format(result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout))
            
            if result.returncode == 12:
                _cerr("")
                _cerr("    Rule/signature issue (code 12): rules may be incomplete or wrong version for capa 9.")
                _cerr("    Delete AskJOE/capa_signatures and run CAPA again to re-download official rules from master.")
                _cerr("    Or download rules for capa 9 from: https://github.com/mandiant/capa-rules/releases")
            else:
                _cerr("[!] This may indicate: invalid file format, corrupted executable, or permissions.")
            return
        
        # Parse CAPA results
        try:
            capa_results = json.loads(result.stdout)
            
            # Validate CAPA output structure
            if not isinstance(capa_results, dict):
                error_msg = "Invalid CAPA output format: expected dict, got {}".format(type(capa_results))
                log_error(logger, error_msg)
                _cerr("[-] {}".format(error_msg))
                return
            
            if 'rules' not in capa_results:
                error_msg = "CAPA output missing 'rules' section"
                log_error(logger, error_msg)
                _cerr("[-] {}".format(error_msg))
                return
            
            log_info(logger, "CAPA analysis completed successfully")
            log_info(logger, "Found {} rules in output".format(len(capa_results['rules'])))
            
            # Process and display results
            display_capa_results(capa_results)
            
        except json.JSONDecodeError as e:
            error_msg = "Failed to parse CAPA JSON output: {}".format(e)
            log_error(logger, error_msg)
            _cerr("[-] {}".format(error_msg))
            return
            
    except subprocess.TimeoutExpired:
        error_msg = "CAPA analysis timed out after 5 minutes"
        log_error(logger, error_msg)
        _cerr("[-] {}".format(error_msg))
    except Exception as e:
        error_msg = "CAPA analysis failed: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        _cerr("[-] {}".format(error_msg))





def extract_address_from_match(match):
    """Extract address from CAPA match structure based on official implementation"""
    try:
        # Handle different CAPA output formats
        if isinstance(match, dict):
            # Look for direct address in match
            if 'address' in match:
                return "0x{:x}".format(match['address'])
            
            # Look for location object
            if 'location' in match:
                location = match['location']
                if isinstance(location, dict):
                    if 'value' in location:
                        return "0x{:x}".format(location['value'])
                    elif 'address' in location:
                        return "0x{:x}".format(location['address'])
            
            # Look for locations array
            if 'locations' in match:
                locations = match['locations']
                if isinstance(locations, list) and len(locations) > 0:
                    location = locations[0]  # Take first location
                    if isinstance(location, dict):
                        if 'value' in location:
                            return "0x{:x}".format(location['value'])
                        elif 'address' in location:
                            return "0x{:x}".format(location['address'])
                        elif 'location' in location:
                            sub_location = location['location']
                            if isinstance(sub_location, dict):
                                if 'value' in sub_location:
                                    return "0x{:x}".format(sub_location['value'])
                                elif 'address' in sub_location:
                                    return "0x{:x}".format(sub_location['address'])
            
            # Look for value directly
            if 'value' in match:
                return "0x{:x}".format(match['value'])
        
        elif isinstance(match, list) and len(match) > 0:
            # Handle list format: [location, features]
            location = match[0]
            if isinstance(location, dict):
                if 'value' in location:
                    return "0x{:x}".format(location['value'])
                elif 'address' in location:
                    return "0x{:x}".format(location['address'])
                elif 'location' in location:
                    sub_location = location['location']
                    if isinstance(sub_location, dict):
                        if 'value' in sub_location:
                            return "0x{:x}".format(sub_location['value'])
                        elif 'address' in sub_location:
                            return "0x{:x}".format(sub_location['address'])
        
        return None
        
    except Exception as e:
        return None

def display_capa_results(capa_results):
    """Display CAPA analysis results in a user-friendly format"""
    try:
        println("=" * 80)
        println("CAPA ANALYSIS RESULTS")
        println("=" * 80)
        
        # Display basic info
        # Display basic file information
        if 'meta' in capa_results:
            meta = capa_results['meta']
            println("File: {}".format(meta.get('sample', {}).get('path', 'Unknown')))
            println("CAPA Version: {}".format(meta.get('version', 'Unknown')))
        
        println()
        

        
        # Display summary statistics
        if 'statistics' in capa_results:
            stats = capa_results['statistics']
            println("SUMMARY:")
            println("  Total Rules: {}".format(stats.get('rules', 0)))
            println("  Matched Rules: {}".format(stats.get('matched', 0)))
        
        # Add threat analysis summary
        if 'rules' in capa_results:
            rules = capa_results['rules']
            println("\nTHREAT ANALYSIS:")
            
            # Count different types of behaviors
            behavior_counts = {}
            for rule_name, rule_info in rules.items():
                # Extract category from rule name or meta
                category = rule_info.get('meta', {}).get('category', 'unknown')
                if category not in behavior_counts:
                    behavior_counts[category] = 0
                behavior_counts[category] += 1
            
            # Display behavior categories
            for category, count in sorted(behavior_counts.items()):
                println("  {}: {} rules".format(category, count))
            
            # Highlight high-risk behaviors
            high_risk_keywords = ['malware', 'trojan', 'backdoor', 'keylogger', 'ransomware', 'spyware']
            high_risk_count = 0
            for rule_name in rules.keys():
                if any(keyword in rule_name.lower() for keyword in high_risk_keywords):
                    high_risk_count += 1
            
            if high_risk_count > 0:
                println("\n  HIGH-RISK BEHAVIORS DETECTED: {} rules".format(high_risk_count))
                println("  RECOMMENDATION: This file exhibits suspicious behavior patterns")
                println("  that may indicate malicious intent. Further analysis recommended.")
        
        println("=" * 80)
        
        # Add results to Ghidra symbol tree
        add_capa_results_to_ghidra(capa_results)
        
    except Exception as e:
        error_msg = "Error displaying CAPA results: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        _cerr("[-] {}".format(error_msg))

def add_capa_results_to_ghidra(capa_results):
    """Add CAPA results to Ghidra symbol tree (inside a program transaction)."""
    try:
        from ghidra.program.model.symbol import SourceType
        
        if 'rules' not in capa_results:
            return
        
        rules = capa_results['rules']
        program = currentProgram
        # All program modifications must run inside a transaction
        tx_id = program.startTransaction("AskJOE CAPA symbols")
        symbol_count = 0
        try:
            symbol_table = program.getSymbolTable()
            capa_namespace = None
            try:
                capa_namespace = symbol_table.getNamespace("AskJOE-CAPA", None)
            except Exception as e:
                log_debug(logger, "Could not find existing namespace: {}".format(e))
            
            if not capa_namespace:
                try:
                    from ghidra.app.cmd.label import CreateNamespacesCmd
                    cmd = CreateNamespacesCmd("AskJOE-CAPA", SourceType.USER_DEFINED)
                    cmd.applyTo(program)
                    capa_namespace = symbol_table.getNamespace("AskJOE-CAPA", None)
                except Exception as e:
                    log_warning(logger, "Could not create namespace: {}".format(e))
                    capa_namespace = symbol_table.getNamespace("", None)
            
            if not capa_namespace:
                log_error(logger, "No valid namespace available for symbol creation")
                return
            

            

            
            for rule_name, rule_info in rules.items():
                if 'matches' in rule_info:
                    matches = rule_info['matches']
                    
                    if isinstance(matches, list):
                        for match in matches:
                            address = extract_address_from_match(match)
                            if address:
                                try:
                                    # Parse address
                                    ghidra_address = program.getAddressFactory().getAddress(address)
                                    if not ghidra_address:
                                        continue
                                    
                                    # Create symbol name
                                    rule_name_display = rule_info.get('meta', {}).get('name', rule_name)
                                    symbol_name = "CAPA_{}".format(rule_name_display.replace(' ', '_'))
                                    
                                    # Create symbol if it doesn't exist
                                    try:
                                        existing_symbol = symbol_table.getSymbol(symbol_name, ghidra_address, capa_namespace)
                                        if not existing_symbol:
                                            symbol_table.createLabel(ghidra_address, symbol_name, capa_namespace, SourceType.USER_DEFINED)
                                            symbol_count += 1
                                            log_debug(logger, "Created symbol {} at address {}".format(symbol_name, address))
                                    except Exception as e:
                                        log_debug(logger, "Could not check/create symbol {} at {}: {}".format(symbol_name, address, e))
                                        continue
                                    
                                    # Add comment with rule description
                                    rule_description = rule_info.get('meta', {}).get('description', 'No description')
                                    code_unit = program.getListing().getCodeUnitAt(ghidra_address)
                                    if code_unit:
                                        comment = "CAPA Rule: {}".format(rule_description)
                                        code_unit.setComment(code_unit.PLATE_COMMENT, comment)
                                        
                                except Exception as e:
                                    log_debug(logger, "Could not create symbol for address {}: {}".format(address, e))
                                    continue
                    elif isinstance(matches, dict):
                        address = extract_address_from_match(matches)
                        if address:
                            try:
                                # Parse address
                                ghidra_address = program.getAddressFactory().getAddress(address)
                                if not ghidra_address:
                                    continue
                                
                                # Create symbol name
                                rule_name_display = rule_info.get('meta', {}).get('name', rule_name)
                                symbol_name = "CAPA_{}".format(rule_name_display.replace(' ', '_'))
                                
                                # Create symbol if it doesn't exist
                                try:
                                    existing_symbol = symbol_table.getSymbol(symbol_name, ghidra_address, capa_namespace)
                                    if not existing_symbol:
                                        symbol_table.createLabel(ghidra_address, symbol_name, capa_namespace, SourceType.USER_DEFINED)
                                        symbol_count += 1
                                        log_debug(logger, "Created symbol {} at address {}".format(symbol_name, address))
                                except Exception as e:
                                    log_debug(logger, "Could not check/create symbol {} at {}: {}".format(symbol_name, address, e))
                                    continue
                                
                                # Add comment with rule description
                                rule_description = rule_info.get('meta', {}).get('description', 'No description')
                                code_unit = program.getListing().getCodeUnitAt(ghidra_address)
                                if code_unit:
                                    comment = "CAPA Rule: {}".format(rule_description)
                                    code_unit.setComment(code_unit.PLATE_COMMENT, comment)
                                    
                            except Exception as e:
                                log_debug(logger, "Could not create symbol for address {}: {}".format(address, e))
                                continue
            
            # If no symbols were created with addresses, create a summary symbol
            if symbol_count == 0:
                try:
                    # Create a summary symbol at the entry point
                    try:
                        entry_point = program.getEntryPoint()
                    except:
                        try:
                            # Alternative method for getting entry point
                            entry_point = program.getSymbolTable().getPrimarySymbol(program.getMinAddress())
                            if entry_point:
                                entry_point = entry_point.getAddress()
                        except:
                            entry_point = None
                    
                    if entry_point:
                        summary_symbol_name = "CAPA_Summary_{}Rules".format(len(rules))
                        existing_summary = symbol_table.getSymbol(summary_symbol_name, entry_point, capa_namespace)
                        if not existing_summary:
                            symbol_table.createLabel(entry_point, summary_symbol_name, capa_namespace, SourceType.USER_DEFINED)
                            symbol_count += 1
                            
                            # Add detailed comment with all rules
                            code_unit = program.getListing().getCodeUnitAt(entry_point)
                            if code_unit:
                                comment_lines = ["CAPA Analysis Summary:"]
                                comment_lines.append("Total Rules: {}".format(len(rules)))
                                comment_lines.append("Matched Rules:")
                                for rule_name, rule_info in rules.items():
                                    rule_description = rule_info.get('meta', {}).get('description', 'No description')
                                    comment_lines.append("  - {}: {}".format(rule_name, rule_description))
                                
                                comment = "\n".join(comment_lines)
                                code_unit.setComment(code_unit.PLATE_COMMENT, comment)
                                
                            log_debug(logger, "Created summary symbol at entry point")
                    else:
                        log_debug(logger, "No entry point found for summary symbol")
                        
                        # Try to create summary symbol at first available address
                        try:
                            first_address = program.getMinAddress()
                            if first_address:
                                summary_symbol_name = "CAPA_Summary_{}Rules".format(len(rules))
                                existing_summary = symbol_table.getSymbol(summary_symbol_name, first_address, capa_namespace)
                                if not existing_summary:
                                    symbol_table.createLabel(first_address, summary_symbol_name, capa_namespace, SourceType.USER_DEFINED)
                                    symbol_count += 1
                                    log_debug(logger, "Created summary symbol at first address")
                        except Exception as e:
                            log_debug(logger, "Could not create summary symbol at first address: {}".format(e))
                            
                except Exception as e:
                    log_debug(logger, "Could not create summary symbol: {}".format(e))
            
            log_info(logger, "CAPA results added to Ghidra symbol tree")
            println("[+] CAPA results added to Ghidra symbol tree under 'AskJOE-CAPA' namespace")
            println("[+] Total symbols created: {}".format(symbol_count))
        finally:
            program.endTransaction(tx_id, True)
        
        # Provide additional guidance for users
        if symbol_count > 0:
            println("[+] Symbols are now available in the Symbol Tree under 'AskJOE-CAPA' namespace")
            println("[+] Double-click on symbols to navigate to the corresponding code locations")
        else:
            println("[!] No specific addresses found in CAPA results")
            println("[+] Check the generated report file for detailed analysis")
            println("[+] The summary symbol at the entry point contains all rule information")
            
    except Exception as e:
        error_msg = "Error adding CAPA results to Ghidra: {}".format(str(e))
        log_error(logger, error_msg, exc_info=True)
        _cerr("[-] {}".format(error_msg))

def run():
    """Main execution function"""
    try:
        log_info(logger, "Starting CAPA Analysis script")
        monitor.setMessage("AskJOE CAPA Analysis is running")
        
        run_capa_analysis("CAPA Analysis")
        
        log_info(logger, "CAPA Analysis script completed successfully")
        println("CAPA Analysis completed successfully!")
        

        
    except Exception as ex:
        error_msg = "CAPA Analysis script failed: {}".format(str(ex))
        log_error(logger, error_msg, exc_info=True)
        _cerr("[-] {}".format(error_msg))

try:
    run()
except Exception as ex:
    error_msg = "Critical error in CAPA Analysis script: {}".format(str(ex))
    log_critical(logger, error_msg, exc_info=True)
    _cerr("[-] {}".format(error_msg))
