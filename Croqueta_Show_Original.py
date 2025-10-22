
from __future__ import print_function
from ghidra.app.script import GhidraScript
from ghidra.framework.preferences import Preferences
from croqueta.config import CLAUDE_MODELS, GROQ_MODELS, OPENAI_MODELS, GEMINI_MODELS, OLLAMA_MODELS, SKIP_PROMPT_CONFIRMATION
from croqueta.api import get_response_from_claude, get_response_from_groq, get_response_from_openai, get_response_from_gemini, get_response_from_ollama
from croqueta.decompiler import decompile_function
from croqueta.gui import show_model_select_dialog

# Java Swing imports
from javax.swing import JDialog, JTextPane, JScrollPane, JButton, JPanel
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import BorderLayout, GridLayout, Color, Font
from javax.swing import SwingUtilities
import re

# -------------------- Dialog Class --------------------
class OriginalCodeDialog(JDialog):
    def __init__(self, function_name, code):
        super(OriginalCodeDialog, self).__init__(None, u"Original Source Code - {}".format(unicode(function_name)), True)
        self.setSize(900, 700)
        self.setLayout(BorderLayout())
        self.code = code

        self.text_pane = JTextPane()
        self.text_pane.setEditable(False)
        self.text_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.text_pane.setText(unicode(code))

        scroll = JScrollPane(self.text_pane)
        self.add(scroll, BorderLayout.CENTER)

        bottom_panel = JPanel(GridLayout(1, 2))
        copy_button = JButton("Copy All", actionPerformed=self.copy_all)
        close_button = JButton("Close", actionPerformed=self.close_dialog)
        bottom_panel.add(copy_button)
        bottom_panel.add(close_button)
        self.add(bottom_panel, BorderLayout.SOUTH)

        self.apply_syntax_highlighting()
        self.setResizable(True)
        self.setLocationRelativeTo(None)

    def copy_all(self, event):
        self.text_pane.selectAll()
        self.text_pane.copy()

    def close_dialog(self, event):
        self.setVisible(False)

    def apply_syntax_highlighting(self):
        doc = self.text_pane.getStyledDocument()
        text = unicode(self.code)

        # Keyword style
        keyword_style = SimpleAttributeSet()
        StyleConstants.setForeground(keyword_style, Color.BLUE)
        StyleConstants.setBold(keyword_style, True)

        # Comment style
        comment_style = SimpleAttributeSet()
        StyleConstants.setForeground(comment_style, Color(0, 128, 0))
        StyleConstants.setItalic(comment_style, True)

        # String style
        string_style = SimpleAttributeSet()
        StyleConstants.setForeground(string_style, Color.RED)

        keywords = [
            "if","else","for","while","do","switch","case","default","return","break",
            "continue","goto","void","int","char","long","short","unsigned","signed",
            "const","static","struct","union","enum","typedef","sizeof","true","false"
        ]

        for kw in keywords:
            start = 0
            while True:
                idx = text.find(kw, start)
                if idx == -1:
                    break
                before = idx == 0 or not text[idx-1].isalnum()
                after = idx + len(kw) >= len(text) or not text[idx + len(kw)].isalnum()
                if before and after:
                    doc.setCharacterAttributes(idx, len(kw), keyword_style, False)
                start = idx + 1

        # Highlight comments
        for match in re.finditer(r'//.*?$|/\*.*?\*/', text, re.MULTILINE | re.DOTALL):
            doc.setCharacterAttributes(match.start(), match.end() - match.start(), comment_style, False)

        # Highlight strings
        for match in re.finditer(r'"[^"]*"|\'[^\']*\'', text):
            doc.setCharacterAttributes(match.start(), match.end() - match.start(), string_style, False)

# -------------------- Helper Function --------------------
def get_api_key(preferences, provider):
    if provider == "Claude":
        key_name = "ANTHROPIC_API_KEY"
    elif provider == "Groq":
        key_name = "GROQ_API_KEY"
    elif provider == "OpenAI":
        key_name = "OPENAI_API_KEY"
    elif provider == "Gemini":
        key_name = "GEMINI_API_KEY"
    else:
        key_name = None
    return preferences.getProperty(key_name) if key_name else None

# -------------------- Main Script --------------------
class CroquetaShowOriginalScript(GhidraScript):
    def run(self):
        self.show_original_code()

    def show_original_code(self):
        func = getFunctionContaining(currentAddress)
        if func is None or currentProgram is None or monitor is None:
            print(u"Required context is missing.")
            return

        # Use Ghidra Preferences
        preferences = Preferences
        provider = preferences.getProperty("DEFAULT_PROVIDER")
        model = preferences.getProperty("DEFAULT_MODEL")

        if not provider or not model:
            provider, model = show_model_select_dialog()
            if not provider or not model:
                print(u"Provider/model selection cancelled.")
                return

        api_key = get_api_key(preferences, provider)
        if not api_key:
            print(u"API key not found. Please run Croqueta settings first.")
            return

        # Decompile function
        decompiled_code, variables = decompile_function(func, currentProgram, monitor)
        if not decompiled_code:
            print(u"Failed to decompile function.")
            return

        prompt = u"""You are looking at decompiled code from a reverse engineering tool.
Rewrite it as clean, human-readable, idiomatic C code.
Keep variable names and logic intact.
Add short, concise comments explaining key steps.
Do not output any tables or long 'what changed' sections, just the code with comments.

DECOMPILED CODE:
{}""".format(unicode(decompiled_code))





        monitor.setMessage(u"Asking AI to show original code style...")

        # Call the AI API
        response = None
        if provider == "Claude":
            response = get_response_from_claude(prompt, api_key, model, monitor, is_explanation=True)
        elif provider == "Groq":
            response = get_response_from_groq(prompt, api_key, model, monitor, is_explanation=True)
        elif provider == "OpenAI":
            response = get_response_from_openai(prompt, api_key, model, monitor, is_explanation=True)
        elif provider == "Gemini":
            response = get_response_from_gemini(prompt, api_key, model, monitor, is_explanation=True)
        elif provider == "Ollama":
            response = get_response_from_ollama(prompt, model, monitor, is_explanation=True)
        else:
            print(u"Unknown provider: {}".format(provider))
            return

        # Show dialog safely
        if response:
            def show_dialog():
                dialog = OriginalCodeDialog(func.getName(), response)
                dialog.setVisible(True)
            SwingUtilities.invokeLater(show_dialog)
            print(u"Original code style displayed for function: {}".format(func.getName()))
        else:
            print(u"Failed to get response from {} API.".format(provider))

        monitor.setMessage(u"")

# -------------------- Entry Point --------------------
if __name__ == "__main__":
    script = CroquetaShowOriginalScript()
    script.run()
