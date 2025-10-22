# api.py

# Note: Croqueta doesn't use Anthropic's official python API as it is intended for Python 3+

import json
import urllib2
import time
import hashlib
import os
from croqueta.config import CLAUDE_API_URL, GROQ_API_URL, OPENAI_API_URL, GEMINI_API_URL, OLLAMA_API_URL, ENABLE_CACHING, CACHE_EXPIRY_HOURS

def send_request(url, headers, data):
    """Send a POST request to the specified URL with the given headers and data.

    Args:
        url (str): The URL to send the request to.
        headers (dict): A dictionary of HTTP headers to include in the request.
        data (dict): The data to send in the body of the request.

    Returns:
        urllib2.Response or urllib2.HTTPError: The response object returned by the server.
    """
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
    """Read the response from the response object.

    Args:
        response (urllib2.Response or urllib2.HTTPError): The response object returned by send_request.

    Returns:
        str: The content of the response as a string, or None if an error occurred.
    """
    if response is None:
        return None
    elif isinstance(response, urllib2.HTTPError):
        error_content = response.read()
        print "Error: HTTP response code {}".format(response.code)
        print "Error message: {}".format(error_content)
        # For debugging, also print the full error details
        try:
            error_json = json.loads(error_content)
            if 'error' in error_json:
                print "Detailed error: {}".format(error_json['error'])
        except:
            pass
        return None
    else:
        content = response.read()
        return content

def parse_json_response(content):
    """Parse the JSON response from Claude API.

    Args:
        content (str): The response content as a string.

    Returns:
        dict: The parsed JSON object, or None if parsing failed.
    """
    json_start = content.find('{')
    json_end = content.rfind('}') + 1
    if json_start != -1 and json_end != -1:
        json_str = content[json_start:json_end]
        try:
            return json.loads(json_str)
        except ValueError as e:
            print "Failed to parse JSON from Claude's response: {}".format(str(e))
    else:
        print "No JSON object found in Claude's response"
    return None

def get_response_from_claude(prompt, api_key, model, monitor, is_explanation=False):
    """Get a response from the Claude API.

    Args:
        prompt (str): The prompt to send to the Claude API.
        api_key (str): The API key for authentication.
        model (str): The model name to use.
        monitor (object): An object with a setMessage method to display status messages.
        is_explanation (bool, optional): Flag indicating if the response is an explanation. Defaults to False.

    Returns:
        dict or str: The parsed JSON response, or the content string if is_explanation is True.
    """
    cache_key = get_cache_key(prompt, model, "Claude")
    cached_response = get_cached_response(cache_key)
    if cached_response:
        return cached_response

    try:
        monitor.setMessage("Sending request to Claude API...")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.2,
            "top_p": 1.0,
            "top_k": 30
        }

        print "Sending request to Claude API..."
        response = send_request(CLAUDE_API_URL, headers, data)

        monitor.setMessage("Waiting for response from Claude API...")
        content = read_response(response)

        if content:
            print "Received response from Claude API."
            response_json = json.loads(content)
            content_text = response_json['content'][0]['text']

            if is_explanation:
                result = content_text.strip()
            else:
                result = parse_json_response(content_text)

            set_cached_response(cache_key, result)
            return result

        return None

    except Exception as e:
        print "Exception in get_response_from_claude: {}".format(e)
        return None
    finally:
        monitor.setMessage("")

def get_response_from_groq(prompt, api_key, model, monitor, is_explanation=False):
    """Get a response from the Groq API.

    Args:
        prompt (str): The prompt to send to the Groq API.
        api_key (str): The API key for authentication.
        model (str): The model name to use.
        monitor (object): An object with a setMessage method to display status messages.
        is_explanation (bool, optional): Flag indicating if the response is an explanation. Defaults to False.

    Returns:
        dict or str: The parsed JSON response, or the content string if is_explanation is True.
    """
    try:
        monitor.setMessage("Sending request to Groq API...")
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(api_key),
            "User-Agent": "Croqueta-Ghidra-Plugin/1.0"
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.2,
            "top_p": 1.0,
            "stream": False
        }

        print "Sending request to Groq API..."
        response = send_request(GROQ_API_URL, headers, data)

        monitor.setMessage("Waiting for response from Groq API...")
        content = read_response(response)

        if content:
            print "Received response from Groq API."
            response_json = json.loads(content)
            content_text = response_json['choices'][0]['message']['content']

            if is_explanation:
                return content_text.strip()
            else:
                return parse_json_response(content_text)

        return None

    except Exception as e:
        print "Exception in get_response_from_groq: {}".format(e)
        return None
    finally:
        monitor.setMessage("")

def get_cache_key(prompt, model, provider):
    """Generate a cache key for the given prompt, model, and provider."""
    key_data = "{}{}{}".format(prompt, model, provider)
    return hashlib.md5(key_data.encode('utf-8')).hexdigest()

def get_cached_response(cache_key):
    """Retrieve a cached response if it exists and is not expired."""
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

            # Check if cache is expired
            cache_time = cache_data.get('timestamp', 0)
            current_time = time.time()
            expiry_time = CACHE_EXPIRY_HOURS * 3600

            if current_time - cache_time < expiry_time:
                return cache_data.get('response')
            else:
                # Cache expired, remove file
                os.remove(cache_file)
        except (IOError, ValueError, KeyError):
            # If cache file is corrupted, remove it
            try:
                os.remove(cache_file)
            except:
                pass

    return None

def set_cached_response(cache_key, response):
    """Cache the response for future use."""
    if not ENABLE_CACHING:
        return

    cache_dir = os.path.join(os.path.expanduser("~"), ".croqueta_cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    cache_file = os.path.join(cache_dir, "{}.json".format(cache_key))

    cache_data = {
        'timestamp': time.time(),
        'response': response
    }

    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)
    except IOError:
        # If we can't write cache, just continue without caching
        pass

def get_response_from_openai(prompt, api_key, model, monitor, is_explanation=False):
    """Get a response from the OpenAI API."""
    try:
        monitor.setMessage("Sending request to OpenAI API...")
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(api_key)
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.2
        }

        response = send_request(OPENAI_API_URL, headers, data)
        content = read_response(response)

        if content:
            response_json = json.loads(content)
            content_text = response_json['choices'][0]['message']['content']

            if is_explanation:
                return content_text.strip()
            else:
                return parse_json_response(content_text)

        return None

    except Exception as e:
        print "Exception in get_response_from_openai: {}".format(e)
        return None
    finally:
        monitor.setMessage("")

def get_response_from_gemini(prompt, api_key, model, monitor, is_explanation=False):
    """Get a response from the Gemini API."""
    try:
        monitor.setMessage("Sending request to Gemini API...")
        url = GEMINI_API_URL.format(model=model)
        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "contents": [{"parts": [{"text": prompt}]}]
        }

        response = send_request(url + "?key=" + api_key, headers, data)
        content = read_response(response)

        if content:
            response_json = json.loads(content)
            content_text = response_json['candidates'][0]['content']['parts'][0]['text']

            if is_explanation:
                return content_text.strip()
            else:
                return parse_json_response(content_text)

        return None

    except Exception as e:
        print "Exception in get_response_from_gemini: {}".format(e)
        return None
    finally:
        monitor.setMessage("")

def get_response_from_ollama(prompt, model, monitor, is_explanation=False):
    """Get a response from the local Ollama API."""
    try:
        monitor.setMessage("Sending request to Ollama API...")
        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }

        response = send_request(OLLAMA_API_URL, headers, data)
        content = read_response(response)

        if content:
            response_json = json.loads(content)
            content_text = response_json['response']

            if is_explanation:
                return content_text.strip()
            else:
                return parse_json_response(content_text)

        return None

    except Exception as e:
        print "Exception in get_response_from_ollama: {}".format(e)
        return None
    finally:
        monitor.setMessage("")
