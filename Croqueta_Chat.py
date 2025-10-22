# Croqueta Chat with safe threading for API calls
# Python extension for Ghidra
# @author Golconda
# @category AI Analysis
# @keybinding Shift C
# @menupath
# @toolbar

from ghidra.app.script import GhidraScript
from ghidra.framework.preferences import Preferences
from croqueta.config import (
    CLAUDE_MODELS, GROQ_MODELS, OPENAI_MODELS, GEMINI_MODELS, OLLAMA_MODELS,
    CLAUDE_API_URL, GROQ_API_URL, OPENAI_API_URL, GEMINI_API_URL, OLLAMA_API_URL,
    ENABLE_CACHING, CACHE_EXPIRY_HOURS
)
from croqueta.decompiler import decompile_function
from croqueta.gui import show_model_select_dialog, show_chat_dialog
import json, urllib2, os, time, hashlib
from threading import Thread

# ------------------ Thread-safe async executor ------------------

def async_request(func, *args, **kwargs):
    """Run a function in a separate thread to avoid Netty executor termination."""
    result_container = {}

    def wrapper():
        try:
            result_container['result'] = func(*args, **kwargs)
        except Exception as e:
            result_container['error'] = e

    t = Thread(target=wrapper)
    t.start()
    t.join()
    if 'error' in result_container:
        raise result_container['error']
    return result_container.get('result')

# ------------------ API utilities ------------------

def send_request(url, headers, data):
    """Thread-safe HTTP POST request."""
    req = urllib2.Request(url, json.dumps(data), headers)
    try:
        response = urllib2.urlopen(req)
        return response
    except urllib2.HTTPError as e:
        return e
    except urllib2.URLError as e:
        print "Failed to reach server: {}".format(e.reason)
        return None

def read_response(response):
    if response is None:
        return None
    elif isinstance(response, urllib2.HTTPError):
        error_content = response.read()
        print "HTTP Error {}: {}".format(response.code, error_content)
        try:
            error_json = json.loads(error_content)
            if 'error' in error_json:
                print "Details: {}".format(error_json['error'])
        except:
            pass
        return None
    else:
        return response.read()

def parse_json_response(content):
    if not content:
        return None
    try:
        return json.loads(content)
    except ValueError:
        return None

def get_cache_key(prompt, model, provider):
    return hashlib.md5("{}{}{}".format(prompt, model, provider).encode('utf-8')).hexdigest()

def get_cached_response(cache_key):
    if not ENABLE_CACHING:
        return None
    cache_dir = os.path.join(os.path.expanduser("~"), ".croqueta_cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    cache_file = os.path.join(cache_dir, "{}.json".format(cache_key))
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            if time.time() - cache_data.get('timestamp', 0) < CACHE_EXPIRY_HOURS * 3600:
                return cache_data.get('response')
            else:
                os.remove(cache_file)
        except:
            try: os.remove(cache_file)
            except: pass
    return None

def set_cached_response(cache_key, response):
    if not ENABLE_CACHING:
        return
    cache_dir = os.path.join(os.path.expanduser("~"), ".croqueta_cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    cache_file = os.path.join(cache_dir, "{}.json".format(cache_key))
    try:
        with open(cache_file, 'w') as f:
            json.dump({'timestamp': time.time(), 'response': response}, f)
    except:
        pass

def get_api_key(preferences, provider):
    key_name = {
        "Claude": "ANTHROPIC_API_KEY",
        "Groq": "GROQ_API_KEY",
        "OpenAI": "OPENAI_API_KEY",
        "Gemini": "GEMINI_API_KEY"
    }.get(provider)
    if key_name:
        return preferences.getProperty(key_name)
    return None

def api_call(provider, url, headers, data):
    return async_request(send_request, url, headers, data)

def get_response_generic(prompt, api_key, model, monitor, provider, api_url_key, is_explanation=False):
    """Unified generic API call function."""
    cache_key = get_cache_key(prompt, model, provider)
    cached = get_cached_response(cache_key)
    if cached:
        return cached

    try:
        monitor.setMessage("Sending request to {} API...".format(provider))
        headers = {"Content-Type": "application/json"}
        if provider != "Ollama":
            if provider == "Claude":
                headers["x-api-key"] = api_key
            else:
                headers["Authorization"] = "Bearer {}".format(api_key)

        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.2
        }
        if provider == "Ollama":
            data = {"model": model, "prompt": prompt, "stream": False}

        response = api_call(provider, api_url_key, headers, data)
        content = read_response(response)
        if content:
            try:
                response_json = json.loads(content)
                if provider in ["Claude", "OpenAI", "Groq"]:
                    content_text = response_json['choices'][0]['message']['content'] if provider != "Claude" else response_json['content'][0]['text']
                elif provider == "Gemini":
                    content_text = response_json['candidates'][0]['content']['parts'][0]['text']
                elif provider == "Ollama":
                    content_text = response_json['response']
                result = content_text.strip() if is_explanation else parse_json_response(content_text)
                set_cached_response(cache_key, result)
                return result
            except Exception as e:
                print "Error parsing response:", e
                return None
        return None
    except Exception as e:
        print "Exception in {} API call: {}".format(provider, e)
        return None
    finally:
        monitor.setMessage("")

# ------------------ Croqueta Chat Script ------------------

class CroquetaChatScript(GhidraScript):
    def run(self):
        self.launch_chat()

    def launch_chat(self):
        func = getFunctionContaining(currentAddress)
        if not func or not currentProgram or not monitor:
            print "Required context is missing. Navigate to a function first."
            return

        preferences = Preferences
        provider = preferences.getProperty("DEFAULT_PROVIDER")
        model = preferences.getProperty("DEFAULT_MODEL")
        if not provider or not model:
            provider, model = show_model_select_dialog()
            if not provider or not model:
                print "Provider/model selection cancelled."
                return

        api_key = get_api_key(preferences, provider)
        if not api_key and provider != "Ollama":
            print "API key not found. Run Croqueta settings first."
            return

        decompiled_code, variables = decompile_function(func, currentProgram, monitor)
        if not decompiled_code:
            print "Failed to decompile function."
            return

        context_prompt = u"""You are an expert reverse engineer analyzing code in Ghidra. You have access to the following decompiled function:

FUNCTION: {func_name}
DECOMPILED CODE:
{code}

Use this context to answer questions about reverse engineering, code analysis, security vulnerabilities, or other aspects. Be specific and technical.""".format(
            func_name=func.getName(),
            code=decompiled_code
        ).encode('utf-8')

        print "Launching Croqueta Chat with context from function: {}".format(func.getName())
        print "You can now ask questions about the reverse engineered code!"

        try:
            # Corrected signature: provider, model, api_key, monitor
            show_chat_dialog(provider, model, api_key, monitor)
        except Exception as e:
            print "Error launching chat dialog:", e

# ------------------ Entry Point ------------------

if __name__ == "__main__":
    script = CroquetaChatScript()
    script.run()
