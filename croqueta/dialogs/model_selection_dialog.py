# model_selection_dialog.py

import threading
import javax.swing as swing
from javax.swing import JFrame, JPanel, JButton, JScrollPane, BoxLayout, JLabel, JComboBox
from java.awt import BorderLayout
from croqueta.config import CLAUDE_MODELS, GROQ_MODELS

class ModelSelectionDialog(JFrame):
    """
    Dialog for selecting the AI provider and model to use.
    """
    def __init__(self, on_selection_complete):
        super(ModelSelectionDialog, self).__init__("Select AI Provider and Model")
        self.selected_provider = None
        self.selected_model = None
        self.on_selection_complete = on_selection_complete
        self.init_ui()

    def init_ui(self):
        try:
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            self.add_provider_label(panel)
            self.add_provider_combo_box(panel)
            self.add_model_label(panel)
            self.add_model_combo_box(panel)
            self.add_buttons(panel)

            self.getContentPane().add(JScrollPane(panel), BorderLayout.CENTER)
            self.setSize(400, 200)
            self.setLocationRelativeTo(None)
            self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.setVisible(True)
        except Exception as e:
            print "Error initializing ModelSelectionDialog UI: {}".format(e)

    def add_provider_label(self, panel):
        try:
            provider_label = JLabel("Select the AI provider:")
            provider_label.setToolTipText("Choose the AI provider (Claude or Groq)")
            panel.add(provider_label)
        except Exception as e:
            print "Error adding provider label: {}".format(e)

    def add_provider_combo_box(self, panel):
        try:
            self.provider_combo_box = JComboBox(["Claude", "Groq"])
            self.provider_combo_box.setSelectedIndex(0)
            self.provider_combo_box.addActionListener(lambda e: self.on_provider_changed())
            self.provider_combo_box.setToolTipText("Select an AI provider")
            panel.add(self.provider_combo_box)
        except Exception as e:
            print "Error adding provider combo box: {}".format(e)

    def add_model_label(self, panel):
        try:
            model_label = JLabel("Select the model to use:")
            model_label.setToolTipText("Choose the desired model")
            panel.add(model_label)
        except Exception as e:
            print "Error adding model label: {}".format(e)

    def add_model_combo_box(self, panel):
        try:
            self.model_combo_box = JComboBox(CLAUDE_MODELS)
            self.model_combo_box.setSelectedIndex(0)
            self.model_combo_box.setToolTipText("Select a model from the dropdown")
            panel.add(self.model_combo_box)
        except Exception as e:
            print "Error adding model combo box: {}".format(e)

    def on_provider_changed(self):
        try:
            provider = self.provider_combo_box.getSelectedItem()
            if provider == "Claude":
                models = CLAUDE_MODELS
            elif provider == "Groq":
                models = GROQ_MODELS
            else:
                models = []
            self.model_combo_box.removeAllItems()
            for model in models:
                self.model_combo_box.addItem(model)
            self.model_combo_box.setSelectedIndex(0)
        except Exception as e:
            print "Error updating model combo box: {}".format(e)

    def add_buttons(self, panel):
        try:
            button_panel = JPanel()
            ok_button = JButton("OK")
            ok_button.addActionListener(lambda e: self.ok())
            ok_button.setToolTipText("Confirm model selection")
            cancel_button = JButton("Cancel")
            cancel_button.addActionListener(lambda e: self.cancel())
            cancel_button.setToolTipText("Cancel model selection")
            button_panel.add(ok_button)
            button_panel.add(cancel_button)
            self.getContentPane().add(button_panel, BorderLayout.SOUTH)
        except Exception as e:
            print "Error adding buttons to ModelSelectionDialog: {}".format(e)

    def ok(self):
        try:
            self.selected_provider = self.provider_combo_box.getSelectedItem()
            self.selected_model = self.model_combo_box.getSelectedItem()
            self.on_selection_complete(self.selected_provider, self.selected_model)
            self.dispose()
        except Exception as e:
            print "Error in OK action of ModelSelectionDialog: {}".format(e)

    def cancel(self):
        try:
            self.selected_provider = None
            self.selected_model = None
            self.on_selection_complete(self.selected_provider, self.selected_model)
            self.dispose()
        except Exception as e:
            print "Error in Cancel action of ModelSelectionDialog: {}".format(e)

def show_model_select_dialog():
    """
    Displays the ModelSelectionDialog and waits for user interaction.

    Returns:
        tuple: (selected_provider, selected_model) or (None, None) if cancelled.
    """
    selected_data = []
    dialog_complete = threading.Event()

    def on_selection(provider, model):
        selected_data.append((provider, model))
        dialog_complete.set()

    def create_dialog():
        ModelSelectionDialog(on_selection)

    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return selected_data[0] if selected_data else (None, None)
