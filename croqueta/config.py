# config.py

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODELS = ["claude-sonnet-4-20250514"]

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODELS = ["llama3-8b-8192", "llama3-70b-8192", "mixtral-8x7b-32768", "openai/gpt-oss-120b"]

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODELS = ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"]

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GEMINI_MODELS = ["gemini-1.5-pro", "gemini-1.5-flash"]

OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODELS = ["llama2", "codellama", "mistral"]

# Set to True to enable fast selection and skip prompt confirmation windows
SKIP_PROMPT_CONFIRMATION = False

# Caching settings
ENABLE_CACHING = True
CACHE_EXPIRY_HOURS = 24

# Default provider and model settings (can be changed via keybindings)
DEFAULT_PROVIDER = "Groq"  # Options: "Claude", "Groq", "OpenAI", "Gemini", "Ollama"
DEFAULT_MODEL = "openai/gpt-oss-120b"  # Will be updated based on provider
DEFAULT_ACTIONS = ["rename_retype", "explanation", "line_comments"]  # Default actions to run

# Default window dimensions
DEFAULT_WINDOW_WIDTH = 750
DEFAULT_WINDOW_HEIGHT = 500

# UI Theme settings
THEME = "light"  # Options: "light", "dark"
CUSTOM_THEMES = {
    "light": {"bg": "#FFFFFF", "fg": "#000000", "accent": "#007BFF"},
    "dark": {"bg": "#2B2B2B", "fg": "#FFFFFF", "accent": "#61DAFB"}
}

# Prompt Templates
PROMPTS = {
    "rename_retype": (
        "Analyze the following decompiled C function code and its variables. Provide the following:\n"
        "1. A suggested concise and descriptive name for the function.\n"
        "2. Suggested new names and data types for each variable, including globals if applicable.\n\n"
        "Respond with a JSON object containing 'function_name' and 'variables' fields. The 'variables' field should be an array of objects, each containing 'old_name', 'new_name', and 'new_type'.\n\n"
    ),
    "explanation": (
        "Provide a brief detailed explanation of the following decompiled C function code and its variables. "
        "The explanation should be in-depth but concise, incorporating any meaningful names where applicable.\n\n"
        "Respond with a plain text explanation, without any formatting.\n\n"
    ),
    "line_comments": (
        "Analyze the following decompiled C function code annotated with addresses. Provide concise, meaningful comments "
        "**only** for important lines or sections of the code. Focus on explaining the purpose or significance of each "
        "important operation.\n\n"
        "Respond with a JSON object where each key is the address (as a string) and the value is the suggested "
        "comment for that line. Only include addresses that need comments.\n\n"
        "Example format:\n"
        "{\n"
        "  \"0x401000\": \"Initialize the device object\",\n"
        "  \"0x401010\": \"Check OS version for compatibility\",\n"
        "  \"0x401020\": \"Create symbolic link for the device\"\n"
        "}\n\n"
    ),
    "vulnerability_detection": (
        "Analyze the following decompiled C function code for potential security vulnerabilities. Look for common issues such as:\n"
        "- Buffer overflows\n"
        "- Format string vulnerabilities\n"
        "- Integer overflows/underflows\n"
        "- Use-after-free\n"
        "- Null pointer dereferences\n"
        "- Race conditions\n\n"
        "Provide a JSON response with 'vulnerabilities' as an array of objects, each containing 'type', 'severity', 'location', and 'description'.\n\n"
    ),
    "multi_language": (
        "Analyze the following decompiled code and determine the most likely original programming language. "
        "Then provide suggestions for renaming and retyping variables/functions in that language's conventions.\n\n"
        "Supported languages: C, C++, Rust, Go, Python, Java, Assembly.\n\n"
        "Respond with JSON: {'language': 'detected_language', 'suggestions': {...}}\n\n"
    )
}

# Global variable patterns
GLOBAL_VARIABLE_PATTERNS = [
    r'\bDAT_[0-9a-fA-F]+\b', # Default Ghidra pattern
    r'\bg_\w+\b' # Most likely renamed by our script
]