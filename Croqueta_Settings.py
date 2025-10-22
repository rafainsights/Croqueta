# Python extension for configuring Croqueta AI provider settings.
# @author Golconda (modified)
# @category AI Analysis
# @keybinding Shift S
# @menupath
# @toolbar

# Ghidra script context
from ghidra.app.script import GhidraScript
from ghidra.framework.preferences import Preferences
from croqueta.config import CLAUDE_MODELS, GROQ_MODELS, OPENAI_MODELS, GEMINI_MODELS, OLLAMA_MODELS, DEFAULT_PROVIDER, DEFAULT_MODEL, DEFAULT_ACTIONS
from croqueta.api import get_response_from_claude, get_response_from_groq
from croqueta.gui import show_model_select_dialog

def save_default_settings(provider, model):
    """
    Save the default provider and model settings to Ghidra preferences.
    """
    preferences = Preferences
    preferences.setProperty("DEFAULT_PROVIDER", provider)
    preferences.setProperty("DEFAULT_MODEL", model)
    preferences.store()
    print "Croqueta default settings saved: Provider={}, Model={}".format(provider, model)

def load_default_settings():
    """
    Load the default provider and model settings from Ghidra preferences.
    """
    preferences = Preferences
    provider = preferences.getProperty("DEFAULT_PROVIDER", DEFAULT_PROVIDER)
    model = preferences.getProperty("DEFAULT_MODEL", DEFAULT_MODEL)
    return provider, model

def show_settings_dialog():
    """
    Display a dialog for configuring default AI provider and model settings.
    """
    current_provider, current_model = load_default_settings()

    # Show model selection dialog to choose new defaults
    provider, model = show_model_select_dialog()
    if provider and model:
        save_default_settings(provider, model)
        print "Croqueta settings updated successfully!"
    else:
        print "Croqueta settings update cancelled."

def main():
    """
    Main entry point for the settings script.
    """
    show_settings_dialog()

class CroquetaSettingsScript(GhidraScript):

    def run(self):
        main()

if __name__ == "__main__":
    script = CroquetaSettingsScript()
    script.run()
