"""
Backward-compatible shim module.

This file exists so older scripts importing `AskJOE.openai_utils` continue to work,
while the implementation has been generalized to support multiple AI providers.

New code should prefer importing from `AskJOE.ai_utils`.
"""

from AskJOE.ai_utils import (  # type: ignore[F401]
    read_config,
    ask_open_ai,
    parse_open_ai_response,
)

