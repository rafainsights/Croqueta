import sys
# Add the parent folder of 'croqueta' to sys.path
sys.path.append("/home/zoquetillo/Documents/vstudio/ghidra_AI_plugin/croqueta")

import threading
from javax.swing import JDialog, JTextArea, JButton, JScrollPane, JPanel, JLabel
from java.awt import BorderLayout, GridLayout
from java.awt.event import ActionListener
from croqueta.config import THEME, CUSTOM_THEMES, PROMPTS  # Now this will work

class CustomPromptDialog(JDialog):
    def __init__(self, parent, action):
        super(CustomPromptDialog, self).__init__(parent, "Custom Prompt for {}".format(action), True)
        self.action = action
        self.custom_prompt = ""
        self.init_ui()

    def init_ui(self):
        self.setSize(500, 400)
        self.setLayout(BorderLayout())

        # Prompt area
        self.prompt_area = JTextArea()
        self.prompt_area.setText(self.get_default_prompt())
        scroll_pane = JScrollPane(self.prompt_area)
        self.add(scroll_pane, BorderLayout.CENTER)

        # Buttons
        self.button_panel = JPanel(GridLayout(1, 2))
        save_button = JButton("Save")
        save_button.addActionListener(self.SaveActionListener(self))
        cancel_button = JButton("Cancel")
        cancel_button.addActionListener(self.CancelActionListener(self))
        self.button_panel.add(save_button)
        self.button_panel.add(cancel_button)
        self.add(self.button_panel, BorderLayout.SOUTH)

        # Apply theme
        self.apply_theme()

    def get_default_prompt(self):
        return PROMPTS.get(self.action, "")

    def apply_theme(self):
        theme_colors = CUSTOM_THEMES.get(THEME, CUSTOM_THEMES['light'])
        from java.awt import Color
        if self.getContentPane():
            self.getContentPane().setBackground(Color.decode(theme_colors.get('bg', '#ffffff')))
        if self.prompt_area:
            self.prompt_area.setBackground(Color.decode(theme_colors.get('bg', '#ffffff')))
            self.prompt_area.setForeground(Color.decode(theme_colors.get('fg', '#000000')))
        if hasattr(self, 'button_panel') and self.button_panel:
            save_button = self.button_panel.getComponent(0)
            cancel_button = self.button_panel.getComponent(1)
            if save_button:
                save_button.setBackground(Color.decode(theme_colors.get('accent', '#cccccc')))
                save_button.setForeground(Color.decode(theme_colors.get('fg', '#000000')))
            if cancel_button:
                cancel_button.setBackground(Color.decode(theme_colors.get('accent', '#cccccc')))
                cancel_button.setForeground(Color.decode(theme_colors.get('fg', '#000000')))

    class SaveActionListener(ActionListener):
        def __init__(self, parent):
            self.parent = parent
        def actionPerformed(self, e):
            self.parent.custom_prompt = self.parent.prompt_area.getText()
            self.parent.setVisible(False)

    class CancelActionListener(ActionListener):
        def __init__(self, parent):
            self.parent = parent
        def actionPerformed(self, e):
            self.parent.custom_prompt = ""
            self.parent.setVisible(False)

def show_custom_prompt_dialog(action):
    custom_prompt = []
    dialog_complete = threading.Event()

    def on_save(prompt):
        custom_prompt.append(prompt)
        dialog_complete.set()

    def create_dialog():
        dialog = CustomPromptDialog(None, action)
        dialog.setVisible(True)
        on_save(dialog.custom_prompt)

    import javax.swing as swing
    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return custom_prompt[0] if custom_prompt else ""
