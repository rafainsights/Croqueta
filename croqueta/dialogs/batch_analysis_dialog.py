# batch_analysis_dialog.py

import threading
from javax.swing import JDialog, JButton, JList, JScrollPane, JPanel, JLabel
from java.awt import BorderLayout, GridLayout
from java.awt.event import ActionListener
from croqueta.config import THEME, CUSTOM_THEMES

class BatchAnalysisDialog(JDialog):
    def __init__(self, parent, functions):
        super(BatchAnalysisDialog, self).__init__(parent, "Batch Analysis", True)
        self.functions = functions
        self.selected_functions = []
        self.init_ui()

    def init_ui(self):
        self.setSize(400, 300)
        self.setLayout(BorderLayout())

        # Function list
        self.function_list = JList(self.functions)
        self.function_list.setSelectionMode(2)  # MULTIPLE_INTERVAL_SELECTION
        scroll_pane = JScrollPane(self.function_list)
        self.add(scroll_pane, BorderLayout.CENTER)

        # Buttons
        button_panel = JPanel(GridLayout(1, 2))
        select_all_button = JButton("Select All")
        select_all_button.addActionListener(self.SelectAllActionListener(self))
        analyze_button = JButton("Analyze Selected")
        analyze_button.addActionListener(self.AnalyzeActionListener(self))
        button_panel.add(select_all_button)
        button_panel.add(analyze_button)
        self.add(button_panel, BorderLayout.SOUTH)

        # Apply theme
        self.apply_theme()

    def apply_theme(self):
        theme_colors = CUSTOM_THEMES.get(THEME, CUSTOM_THEMES['light'])
        # Apply colors to dialog components
        from java.awt import Color
        if self.getContentPane():
            self.getContentPane().setBackground(Color.decode(theme_colors.get('bg', '#ffffff')))
        if self.function_list:
            self.function_list.setBackground(Color.decode(theme_colors.get('bg', '#ffffff')))
            self.function_list.setForeground(Color.decode(theme_colors.get('fg', '#000000')))
        if hasattr(self, 'button_panel') and self.button_panel:
            select_all_button = self.button_panel.getComponent(0)
            analyze_button = self.button_panel.getComponent(1)
            if select_all_button:
                select_all_button.setBackground(Color.decode(theme_colors.get('accent', '#cccccc')))
                select_all_button.setForeground(Color.decode(theme_colors.get('fg', '#000000')))
            if analyze_button:
                analyze_button.setBackground(Color.decode(theme_colors.get('accent', '#cccccc')))
                analyze_button.setForeground(Color.decode(theme_colors.get('fg', '#000000')))

    class SelectAllActionListener(ActionListener):
        def __init__(self, parent):
            self.parent = parent

        def actionPerformed(self, e):
            self.parent.function_list.setSelectionInterval(0, len(self.parent.functions) - 1)

    class AnalyzeActionListener(ActionListener):
        def __init__(self, parent):
            self.parent = parent

        def actionPerformed(self, e):
            self.parent.selected_functions = list(self.parent.function_list.getSelectedValues())
            self.parent.setVisible(False)

# Helper Functions
def show_batch_analysis_dialog(functions):
    """
    Displays the BatchAnalysisDialog and waits for user interaction.

    Args:
        functions: List of function names to display

    Returns:
        list: The list of selected functions or an empty list if none selected.
    """
    selected_functions = []
    dialog_complete = threading.Event()

    def on_selection(selected):
        selected_functions.extend(selected)
        dialog_complete.set()

    def create_dialog():
        dialog = BatchAnalysisDialog(None, functions)
        dialog.setVisible(True)
        on_selection(dialog.selected_functions)

    import javax.swing as swing
    swing.SwingUtilities.invokeLater(create_dialog)
    dialog_complete.wait()
    return selected_functions
