import configparser
import logging
import os

# For type checking
try:
    from ghidra.ghidra_builtins import *
except ImportError:
    pass

try:
    from ghidra.app.script import GhidraScriptUtil
except ImportError:
    GhidraScriptUtil = None

# Suppress INFO messages from httpx (used by AI clients)
logging.getLogger("httpx").setLevel(logging.WARNING)


def read_config(section_name, key_name):
    """Read configuration from config file."""
    try:
        config_path = _get_config_path()
        if not config_path:
            return ""
        config = configparser.ConfigParser()
        config.read(config_path)

        # Check if section and key exist
        if not config.has_section(section_name) or not config.has_option(
            section_name, key_name
        ):
            return ""

        return str(config.get(section_name, key_name))

    except Exception:
        return ""


def _get_config_path():
    """Return path to config.ini, or None if not found."""
    try:
        if GhidraScriptUtil is not None:
            try:
                ghidra_script = GhidraScriptUtil()
                candidate = os.path.join(ghidra_script.USER_SCRIPTS_DIR, "AskJOE", "config.ini")
                if os.path.isfile(candidate):
                    return candidate
            except Exception:
                pass
        _askjoe_dir = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(_askjoe_dir, "config.ini")
        if os.path.isfile(candidate):
            return candidate
    except Exception:
        pass
    return None


def write_config(section_name, key_name, value):
    """Write a single key to config.ini. Creates section/key if missing. Returns True on success."""
    config_path = _get_config_path()
    if not config_path:
        return False
    try:
        config = configparser.ConfigParser()
        config.read(config_path)
        if not config.has_section(section_name):
            config.add_section(section_name)
        config.set(section_name, key_name, str(value))
        with open(config_path, "w", encoding="utf-8") as f:
            config.write(f)
        return True
    except Exception:
        return False


def _get_ai_provider():
    """
    Determine which AI provider to use.

    Defaults to 'openai' if no [AI] section or provider is configured.
    """
    provider = read_config("AI", "provider")
    if not provider:
        return "openai"

    provider = provider.strip().lower()
    if provider in ("claude", "anthropic"):
        return "claude"
    return "openai"


def ask_open_ai(prompt, decompiled_function=""):
    """
    Make an AI API call through the configured provider.

    - When [AI].provider = 'claude' or 'anthropic', this uses Anthropic Claude.
    - Otherwise, it falls back to the OpenAI chat.completions API.
    """
    full_prompt = "{}\n{}".format(prompt, decompiled_function)

    provider = _get_ai_provider()

    # Claude / Anthropic path
    if provider == "claude":
        try:
            try:
                from anthropic import Anthropic
            except ImportError as import_error:
                print("[-] Anthropic (Claude) module not available: {}".format(import_error))
                print("    Please install it with: pip install anthropic")
                return None

            # Prefer config value, fall back to environment variable
            api_key = read_config("API_KEYS", "claude_api_key") or os.getenv(
                "ANTHROPIC_API_KEY", ""
            )
            if not api_key or len(api_key) < 20:
                print("[-] Invalid or missing Claude API key")
                print("    Set [API_KEYS].claude_api_key in config.ini or ANTHROPIC_API_KEY env var.")
                return None

            client = Anthropic(api_key=api_key)

            model = read_config("AI", "claude_model") or "claude-sonnet-4-6"

            response = client.messages.create(
                model=model,
                messages=[{"role": "user", "content": full_prompt}],
                max_tokens=2048,
                temperature=0.8,
            )

            # Convert Claude response into plain text so callers can treat it
            # like an already-parsed string and reuse existing parsing logic.
            try:
                parts = getattr(response, "content", None)
                if not parts and isinstance(response, dict):
                    parts = response.get("content", [])

                text_chunks = []
                if parts:
                    for part in parts:
                        # SDK objects
                        if hasattr(part, "type") and getattr(part, "type") == "text":
                            text = getattr(part, "text", None)
                            if text:
                                text_chunks.append(text)
                        # Dict-style
                        elif isinstance(part, dict) and part.get("type") == "text":
                            text = part.get("text")
                            if text:
                                text_chunks.append(text)

                if text_chunks:
                    return "\n".join(text_chunks)

                # Fallback: best-effort string conversion
                return str(response)

            except Exception as parse_error:
                print("[-] Error parsing Claude response: {}".format(parse_error))
                return str(response)

        except Exception as e:
            print("[-] Claude API call failed: {}".format(e))
            return None

    # Default: OpenAI path (backwards compatible)
    try:
        try:
            from openai import OpenAI
        except ImportError as import_error:
            print("[-] OpenAI module not available: {}".format(import_error))
            print("    Either install openai or switch [AI].provider to 'claude'.")
            return None

        # Get API key
        api_key = read_config("API_KEYS", "openai_api_key")
        if not api_key or len(api_key) < 20:
            print("[-] Invalid or missing OpenAI API key")
            return None

        client = OpenAI(api_key=api_key)

        # Make API call
        model = read_config("AI", "openai_model") or "gpt-3.5-turbo"
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": full_prompt}],
            temperature=0.8,
            max_tokens=2048,
            top_p=1,
            frequency_penalty=0.2,
            presence_penalty=0,
        )

        return response

    except Exception as e:
        print("[-] OpenAI API call failed: {}".format(e))
        return None


def parse_open_ai_response(response):
    """Parse an AI response into plain text.

    Works for:
    - Already-parsed strings (including Claude responses from ask_open_ai)
    - OpenAI chat.completions style dicts
    - OpenAI Python SDK response objects
    """
    try:
        if not response:
            return "No response received from AI"

        # Check if it's a string (already parsed or Claude text)
        if isinstance(response, str):
            return response

        # Check if it's a dict (JSON response)
        if isinstance(response, dict):
            if "choices" in response and len(response["choices"]) > 0:
                if (
                    "message" in response["choices"][0]
                    and "content" in response["choices"][0]["message"]
                ):
                    return response["choices"][0]["message"]["content"]
                else:
                    return "Response format error: missing message content"
            else:
                return "Response format error: no choices found"

        # Check if it's an OpenAI response object
        if hasattr(response, "choices") and len(response.choices) > 0:
            choice = response.choices[0]
            if hasattr(choice, "message") and hasattr(choice.message, "content"):
                return choice.message.content
            else:
                return "Response format error: choice missing message content"
        else:
            return "Response format error: missing choices attribute"

    except Exception as e:
        return "Error parsing response: {}".format(e)

