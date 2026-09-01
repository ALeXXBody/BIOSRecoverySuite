"""Application stylesheet for modern dark theme."""

DARK_THEME = """
* {
    font-family: 'Segoe UI', 'Noto Sans', sans-serif;
    font-size: 13px;
    color: #E0E0E0;
}

QMainWindow, QWidget {
    background-color: #1E1E2E;
}

QTabWidget::pane {
    border: 1px solid #333;
    border-radius: 4px;
    background-color: #252537;
    top: -1px;
}

QTabBar::tab {
    background-color: #2A2A3E;
    color: #AAA;
    padding: 10px 20px;
    border: 1px solid #333;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background-color: #3B5BDB;
    color: #FFFFFF;
}

QTabBar::tab:hover:!selected {
    background-color: #35354A;
}

QPushButton {
    background-color: #3B5BDB;
    color: #FFFFFF;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #4A6AE0;
}

QPushButton:pressed {
    background-color: #2E4BB5;
}

QPushButton:disabled {
    background-color: #444;
    color: #888;
}

QPushButton[secondary="true"] {
    background-color: #424259;
}

QPushButton[secondary="true"]:hover {
    background-color: #4E4E6A;
}

QPushButton[danger="true"] {
    background-color: #D64545;
}

QPushButton[danger="true"]:hover {
    background-color: #E05555;
}

QPushButton[success="true"] {
    background-color: #27AE60;
}

QPushButton[success="true"]:hover {
    background-color: #2FBF6F;
}

QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background-color: #2C2C40;
    color: #E0E0E0;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: #3B5BDB;
}

QLineEdit:focus, QComboBox:focus {
    border-color: #3B5BDB;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox QAbstractItemView {
    background-color: #2C2C40;
    color: #E0E0E0;
    border: 1px solid #444;
    selection-background-color: #3B5BDB;
}

QCheckBox {
    color: #E0E0E0;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #555;
    border-radius: 3px;
    background-color: #2C2C40;
}

QCheckBox::indicator:checked {
    background-color: #3B5BDB;
    border-color: #3B5BDB;
}

QGroupBox {
    border: 1px solid #383855;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
    color: #BBB;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #8E8EF0;
}

QTableWidget, QTableView {
    background-color: #26263A;
    alternate-background-color: #2A2A40;
    gridline-color: #333;
    border: 1px solid #383855;
    selection-background-color: #3B5BDB;
    selection-color: #FFFFFF;
}

QHeaderView::section {
    background-color: #2E2E44;
    color: #CCC;
    border: 1px solid #3A3A55;
    padding: 6px;
    font-weight: 600;
}

QProgressBar {
    border: 1px solid #383855;
    border-radius: 4px;
    text-align: center;
    background-color: #2C2C40;
    color: #FFF;
}

QProgressBar::chunk {
    background-color: #3B5BDB;
    border-radius: 3px;
}

QStatusBar {
    background-color: #15151F;
    color: #AAA;
}

QScrollBar:vertical {
    background-color: #26263A;
    width: 12px;
    border-radius: 6px;
}

QScrollBar::handle:vertical {
    background-color: #444466;
    border-radius: 6px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background-color: #55557A;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}

QMenuBar {
    background-color: #1E1E2E;
    color: #E0E0E0;
}

QMenuBar::item:selected {
    background-color: #3B5BDB;
}

QMenu {
    background-color: #26263A;
    border: 1px solid #333;
    color: #E0E0E0;
}

QMenu::item:selected {
    background-color: #3B5BDB;
}

QToolTip {
    background-color: #2E2E44;
    color: #E0E0E0;
    border: 1px solid #3B5BDB;
    padding: 4px;
}

QListWidget {
    background-color: #26263A;
    color: #E0E0E0;
    border: 1px solid #383855;
}

QListWidget::item:selected {
    background-color: #3B5BDB;
    color: #FFFFFF;
}
"""

LIGHT_THEME = """
* {
    font-family: 'Segoe UI', 'Noto Sans', sans-serif;
    font-size: 13px;
    color: #2D2D2D;
}

QMainWindow, QWidget {
    background-color: #F5F5F7;
}

QTabWidget::pane {
    border: 1px solid #D0D0D0;
    border-radius: 4px;
    background-color: #FFFFFF;
    top: -1px;
}

QTabBar::tab {
    background-color: #E8E8EC;
    color: #555;
    padding: 10px 20px;
    border: 1px solid #D0D0D0;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background-color: #3B5BDB;
    color: #FFFFFF;
}

QPushButton {
    background-color: #3B5BDB;
    color: #FFFFFF;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #4A6AE0;
}

QPushButton:disabled {
    background-color: #CCC;
    color: #888;
}

QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background-color: #FFFFFF;
    color: #2D2D2D;
    border: 1px solid #C0C0C0;
    border-radius: 4px;
    padding: 6px 8px;
}

QLineEdit:focus, QComboBox:focus {
    border-color: #3B5BDB;
}

QGroupBox {
    border: 1px solid #D0D0D0;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
}

QTableWidget, QTableView {
    background-color: #FFFFFF;
    alternate-background-color: #F0F0F5;
    gridline-color: #E0E0E0;
    selection-background-color: #3B5BDB;
    selection-color: #FFFFFF;
}

QHeaderView::section {
    background-color: #E8E8EC;
    color: #333;
    border: 1px solid #D0D0D0;
    padding: 6px;
    font-weight: 600;
}

QProgressBar {
    border: 1px solid #D0D0D0;
    border-radius: 4px;
    text-align: center;
    background-color: #F0F0F0;
}

QProgressBar::chunk {
    background-color: #3B5BDB;
    border-radius: 3px;
}

QStatusBar {
    background-color: #E8E8EC;
    color: #555;
}

QMenuBar {
    background-color: #F5F5F7;
    color: #333;
}

QMenuBar::item:selected {
    background-color: #3B5BDB;
    color: #FFF;
}

QMenu {
    background-color: #FFFFFF;
    border: 1px solid #D0D0D0;
    color: #333;
}

QMenu::item:selected {
    background-color: #3B5BDB;
    color: #FFF;
}
"""


def apply_stylesheet(app, dark: bool = True):
    """Apply the selected theme to the application."""
    app.setStyleSheet(DARK_THEME if dark else LIGHT_THEME)
