# Python extension for batch analysis of multiple functions using AI.
# @author Golconda
# @category AI Analysis
# @keybinding Shift B
# @menupath
# @toolbar

from ghidra.app.script import GhidraScript
from ghidra.framework.preferences import Preferences
from croqueta.config import CLAUDE_MODELS, GROQ_MODELS, OPENAI_MODELS, GEMINI_MODELS, OLLAMA_MODELS, DEFAULT_PROVIDER, DEFAULT_MODEL, DEFAULT_ACTIONS
from croqueta.api import get_response_from_claude, get_response_from_groq, get_response_from_openai, get_response_from_gemini, get_response_from_ollama
from croqueta.decompiler import decompile_function, decompile_callers
from croqueta.utils import (
    apply_selected_suggestions, apply_line_comments, apply_explanation,
    prepare_prompt
)
from croqueta.gui import show_batch_analysis_dialog, show_model_select_dialog, show_action_select_dialog

def get_api_key(preferences, provider):
    """
    Retrieve the API key from Ghidra's preferences.
    """
    if provider == "Claude":
        key_name = "ANTHROPIC_API_KEY"
    elif provider == "Groq":
        key_name = "GROQ_API_KEY"
    elif provider == "OpenAI":
        key_name = "OPENAI_API_KEY"
    elif provider == "Gemini":
        key_name = "GEMINI_API_KEY"
    elif provider == "Ollama":
        return None  # Ollama doesn't need key
    else:
        return None

    return preferences.getProperty(key_name)

def process_batch_action(action, func, current_program, monitor, api_key, provider, model, callers_code):
    """
    Process a specific action on the decompiled function for batch analysis.
    """
    decompiled_code, variables = decompile_function(func, current_program, monitor, annotate_addresses=(action == 'line_comments'))
    if not decompiled_code or not variables:
        print "Failed to obtain decompiled code or variable information for {} in function {}.".format(action, func.getName())
        return False

    prompt = prepare_prompt(decompiled_code, variables, action=action, callers_code=callers_code)
    final_prompt = prompt  # Skip confirmation for batch

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
        print "Failed to get {} from {} API for function {}.".format(action.replace('_', ' '), provider, func.getName())
        return False

    if action == 'rename_retype':
        # For batch, apply suggestions automatically without dialog
        try:
            import json
            suggestions = json.loads(response)
            apply_selected_suggestions(func, suggestions, suggestions, None)  # Pass None for tool since we skip dialogs
        except:
            print "Failed to parse rename_retype response for function {}.".format(func.getName())
            return False
    elif action == 'explanation':
        apply_explanation(func, response)
    elif action == 'line_comments':
        try:
            import json
            comments = json.loads(response)
            apply_line_comments(func, comments)
        except:
            print "Failed to parse line_comments response for function {}.".format(func.getName())
            return False

    return True

class CroquetaBatchScript(GhidraScript):
    def run(self):
        self.run_batch_analysis()

    def run_batch_analysis(self):
        """
        Runs batch analysis on multiple selected functions.
        """
        # Get all functions in the program
        function_manager = currentProgram.getFunctionManager()
        all_functions = list(function_manager.getFunctions(True))  # True for forward iteration

        if not all_functions:
            print "No functions found in the program."
            return

        # Get function names for selection
        function_names = [func.getName() for func in all_functions]

        # Show batch analysis dialog
        selected_names = show_batch_analysis_dialog(function_names)
        if not selected_names:
            print "No functions selected for batch analysis."
            return

        # Get selected functions
        selected_functions = [func for func in all_functions if func.getName() in selected_names]

        # Get provider and model
        preferences = Preferences
        provider = preferences.getProperty("DEFAULT_PROVIDER", DEFAULT_PROVIDER)
        model = preferences.getProperty("DEFAULT_MODEL", DEFAULT_MODEL)

        if not provider or not model:
            provider, model = show_model_select_dialog()
            if not provider or not model:
                print "Provider and model selection cancelled."
                return

        api_key = get_api_key(preferences, provider)
        if not api_key and provider != "Ollama":
            print "API key not found. Please run Croqueta settings first."
            return

        # Get actions to perform
        selected_actions = show_action_select_dialog()
        if not selected_actions:
            print "No actions selected."
            return

        print "Starting batch analysis on {} functions with actions: {}".format(len(selected_functions), ", ".join(selected_actions))

        # Process each function
        processed_count = 0
        for func in selected_functions:
            print "Processing function: {}".format(func.getName())
            monitor.setMessage("Processing function: {}".format(func.getName()))

            # For batch, skip callers code to speed up
            callers_code = None

            success = True
            for action in selected_actions:
                if not process_batch_action(action, func, currentProgram, monitor, api_key, provider, model, callers_code):
                    success = False
                    break

            if success:
                processed_count += 1
            else:
                print "Failed to process function: {}".format(func.getName())

        monitor.setMessage("")
        print "Batch analysis completed. Successfully processed {} out of {} functions.".format(processed_count, len(selected_functions))

if __name__ == "__main__":
    script = CroquetaBatchScript()
    script.run()
