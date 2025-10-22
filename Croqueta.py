from ghidra.framework.preferences import Preferences
from croqueta.config import CLAUDE_MODELS, GROQ_MODELS, OPENAI_MODELS, GEMINI_MODELS, OLLAMA_MODELS, SKIP_PROMPT_CONFIRMATION
from croqueta.api import get_response_from_claude, get_response_from_groq, get_response_from_openai, get_response_from_gemini, get_response_from_ollama
from croqueta.decompiler import decompile_function, decompile_callers
from croqueta.utils import (
    apply_selected_suggestions, apply_line_comments, apply_explanation,
    prepare_prompt
)
from croqueta.gui import *

def get_api_key(preferences, provider):
    """
    Retrieve the API key from Ghidra's preferences. If the key does not exist,
    prompt the user to input the API key for the specified provider and store it in the preferences.
    """
    if provider == "Claude":
        key_name = "ANTHROPIC_API_KEY"
        provider_name = "Anthropic Claude"
    elif provider == "Groq":
        key_name = "GROQ_API_KEY"
        provider_name = "Groq"
    elif provider == "OpenAI":
        key_name = "OPENAI_API_KEY"
        provider_name = "OpenAI"
    elif provider == "Gemini":
        key_name = "GEMINI_API_KEY"
        provider_name = "Google Gemini"
    elif provider == "Ollama":
        key_name = None  # Ollama doesn't require an API key
        provider_name = "Ollama"
    else:
        key_name = None
        provider_name = provider

    if key_name:
        api_key = preferences.getProperty(key_name)
        if not api_key:
            api_key = askString("API Key", "Enter your {} API key:".format(provider_name), "")
            if api_key:
                preferences.setProperty(key_name, api_key)
                preferences.store()
                print "{} API Key stored in {}.".format(provider_name, preferences.getFilename())
        return api_key
    else:
        return None  # For providers like Ollama that don't need keys

def get_callers_code(func, current_program, monitor):
    """
    Get the decompiled code of the functions that call the current function.
    This is useful for additional context in the analysis.
    """
    callers = func.getCallingFunctions(monitor)
    if not callers:
        return None
    
    print "Found {} caller(s) for the current function.".format(len(callers))
    selected_callers = show_caller_selection_dialog(list(callers), current_program, monitor)
    return decompile_callers(selected_callers, current_program, monitor) if selected_callers else None

def process_action(action, func, current_program, monitor, api_key, provider, model, callers_code):
    """
    Process a specific action on the decompiled function, sending the data to the selected API and applying the response.
    Actions can include renaming, retyping variables, adding explanations, and inserting line comments.
    """
    decompiled_code, variables = decompile_function(func, current_program, monitor, annotate_addresses=(action == 'line_comments'))
    if not decompiled_code or not variables:
        print "Failed to obtain decompiled code or variable information for {}.".format(action)
        return False

    prompt = prepare_prompt(decompiled_code, variables, action=action, callers_code=callers_code)
    final_prompt = prompt if SKIP_PROMPT_CONFIRMATION else show_prompt_review_dialog(prompt, "Review and Edit Prompt ({})".format(action.replace('_', ' ').title()))
    if not final_prompt:
        print "Prompt review cancelled by user."
        return False

    is_explanation = action == 'explanation'
    if provider == "Claude":
        response = get_response_from_claude(final_prompt, api_key, model, monitor, is_explanation=is_explanation)
    elif provider == "Groq":
        response = get_response_from_groq(final_prompt, api_key, model, monitor, is_explanation=is_explanation)
    elif provider == "OpenAI":
        response = get_response_from_openai(final_prompt, api_key, model, monitor, is_explanation=is_explanation)
    elif provider == "Gemini":
        response = get_response_from_gemini(final_prompt, api_key, model, monitor, is_explanation=is_explanation)
    elif provider == "Ollama":
        response = get_response_from_ollama(final_prompt, model, monitor, is_explanation=is_explanation)
    else:
        print "Unknown provider: {}".format(provider)
        return False

    if not response:
        print "Failed to get {} from {} API.".format(action.replace('_', ' '), provider)
        return False

    if action == 'rename_retype':
        selected_suggestions = show_suggestion_dialog(response, variables, state.getTool())
        if selected_suggestions:
            apply_selected_suggestions(func, response, selected_suggestions, state.getTool())
        else:
            print "Operation cancelled by user after receiving suggestions."
            return False
    elif action == 'explanation':
        apply_explanation(func, response)
    elif action == 'line_comments':
        apply_line_comments(func, response)

    return True

def main():
    """
    The main entry point of the script. Responsible for gathering API keys,
    selecting provider and models, and processing the actions on the current function.
    """
    provider, model = show_model_select_dialog()
    if not provider or not model:
        print "Provider and model selection cancelled by user."
        return

    api_key = get_api_key(Preferences, provider)
    if not api_key:
        print "API key is required to proceed."
        return

    selected_actions = show_action_select_dialog()
    if not selected_actions:
        print "No actions selected. Exiting."
        return

    func = getFunctionContaining(currentAddress)
    if not func or not currentProgram or not monitor:
        print "Required context is missing."
        return

    callers_code = get_callers_code(func, currentProgram, monitor)
    print "Callers' code {}.".format("included for additional context" if callers_code else "not included")

    for action in selected_actions:
        print "Processing action: {}".format(action)
        if not process_action(action, func, currentProgram, monitor, api_key, provider, model, callers_code):
            print "Failed to process action: {}".format(action)
            return

    print "Croqueta operations completed successfully."

if __name__ == "__main__":
    main()
