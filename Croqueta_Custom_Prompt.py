# Python extension for customizing AI prompts used by Croqueta.
# @author Golconda
# @category AI Analysis
# @keybinding Shift P
# @menupath
# @toolbar

from ghidra.app.script import GhidraScript
from ghidra.framework.preferences import Preferences
from croqueta.config import PROMPTS
from croqueta.gui import show_custom_prompt_dialog

class CroquetaCustomPromptScript(GhidraScript):
    def run(self):
        self.customize_prompts()

    def customize_prompts(self):
        """
        Allows users to customize the AI prompts used by Croqueta.
        """
        print "Croqueta Custom Prompt Editor"
        print "Available actions to customize:"
        for action in PROMPTS.keys():
            print "  - {}".format(action.replace('_', ' '.title()))

        # Let user choose which prompt to edit
        action = askChoice("Select Action", "Choose the action whose prompt you want to customize:",
                          list(PROMPTS.keys()), PROMPTS.keys()[0])

        if not action:
            print "No action selected."
            return

        # Show current prompt
        current_prompt = PROMPTS.get(action, "")
        print "\nCurrent prompt for '{}':\n{}".format(action.replace('_', ' ').title(), current_prompt)

        # Show custom prompt dialog
        custom_prompt = show_custom_prompt_dialog(action)
        if not custom_prompt:
            print "Prompt customization cancelled."
            return

        # Save to preferences (since config.py is read-only in Ghidra)
        preferences = Preferences
        pref_key = "CUSTOM_PROMPT_{}".format(action.upper())
        preferences.setProperty(pref_key, custom_prompt)
        preferences.store()

        print "Custom prompt for '{}' saved successfully!".format(action.replace('_', ' ').title())
        print "The custom prompt will be used in future Croqueta operations."

if __name__ == "__main__":
    script = CroquetaCustomPromptScript()
    script.run()
