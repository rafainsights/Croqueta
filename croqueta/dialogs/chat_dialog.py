import threading
from javax.swing import JFrame, JTextArea, JTextField, JButton, JScrollPane, JPanel, SwingUtilities
from java.awt import BorderLayout, GridLayout, Color
from java.awt.event import ActionListener
from croqueta.config import THEME, CUSTOM_THEMES
from croqueta.api import (
    get_response_from_claude,
    get_response_from_groq,
    get_response_from_openai,
    get_response_from_gemini,
    get_response_from_ollama
)

class ChatDialog(JFrame):
    def __init__(self, provider, model, api_key, monitor):
        super(ChatDialog, self).__init__("Croqueta Chat")
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.monitor = monitor
        self.init_ui()

    def init_ui(self):
        self.setSize(600, 400)
        self.setLayout(BorderLayout())

        self.chat_area = JTextArea()
        self.chat_area.setEditable(False)
        scroll_pane = JScrollPane(self.chat_area)
        self.add(scroll_pane, BorderLayout.CENTER)

        self.input_panel = JPanel(GridLayout(1, 2))
        self.input_field = JTextField()
        send_button = JButton("Send")
        send_button.addActionListener(self.SendActionListener(self))
        self.input_panel.add(self.input_field)
        self.input_panel.add(send_button)
        self.add(self.input_panel, BorderLayout.SOUTH)

        self.apply_theme()

    def apply_theme(self):
        theme_colors = CUSTOM_THEMES.get(THEME, CUSTOM_THEMES['light'])
        self.getContentPane().setBackground(Color.decode(theme_colors.get('bg', '#ffffff')))
        self.chat_area.setBackground(Color.decode(theme_colors.get('bg', '#ffffff')))
        self.chat_area.setForeground(Color.decode(theme_colors.get('fg', '#000000')))
        self.input_field.setBackground(Color.decode(theme_colors.get('bg', '#ffffff')))
        self.input_field.setForeground(Color.decode(theme_colors.get('fg', '#000000')))
        send_button = self.input_panel.getComponent(1)
        if send_button:
            send_button.setBackground(Color.decode(theme_colors.get('accent', '#cccccc')))

    class SendActionListener(ActionListener):
        def __init__(self, parent):
            self.parent = parent

        def actionPerformed(self, e):
            user_message = self.parent.input_field.getText().strip()
            if not user_message:
                return

            self.parent.chat_area.append("You: " + user_message + "\n")
            self.parent.input_field.setText("")

            # Run AI request in a background thread
            threading.Thread(target=self.parent.get_response_thread, args=(user_message,)).start()

    def get_response_thread(self, prompt):
        response = self.get_ai_response(prompt)
        if not response:
            response = "[No response]"

        # Update chat area on Swing thread
        def append_response():
            self.chat_area.append("AI: {}\n".format(response))
        SwingUtilities.invokeLater(append_response)

    def get_ai_response(self, prompt):
        if self.provider == "Claude":
            return get_response_from_claude(prompt, self.api_key, self.model, self.monitor, is_explanation=True)
        elif self.provider == "Groq":
            return get_response_from_groq(prompt, self.api_key, self.model, self.monitor, is_explanation=True)
        elif self.provider == "OpenAI":
            return get_response_from_openai(prompt, self.api_key, self.model, self.monitor, is_explanation=True)
        elif self.provider == "Gemini":
            return get_response_from_gemini(prompt, self.api_key, self.model, self.monitor, is_explanation=True)
        elif self.provider == "Ollama":
            return get_response_from_ollama(prompt, self.model, self.monitor, is_explanation=True)
        else:
            return "[Unknown provider]"


def show_chat_dialog(provider, model, api_key, monitor):
    def create_dialog():
        dialog = ChatDialog(provider, model, api_key, monitor)
        dialog.setVisible(True)

    import javax.swing as swing
    swing.SwingUtilities.invokeLater(create_dialog)
