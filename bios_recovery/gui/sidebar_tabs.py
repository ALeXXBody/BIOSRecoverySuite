"""Compact sidebar navigation that replaces QTabWidget.

Implements the subset of the QTabWidget API used by MainWindow so that every
existing tab widget and handler keeps working unchanged. Tabs are listed in a
narrow left sidebar; the selected page fills the remaining space. Disabled
entries stay visible (greyed out) with their tooltip explaining why.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QListWidget, QListWidgetItem, QStackedWidget, QWidget

SIDEBAR_STYLE = """
QListWidget#sidebarNav {
    background-color: #181825;
    border: none;
    border-right: 1px solid #313244;
    outline: none;
    padding: 6px 0;
}
QListWidget#sidebarNav::item {
    color: #CDD6F4;
    padding: 7px 14px;
    border-left: 3px solid transparent;
}
QListWidget#sidebarNav::item:hover:!selected {
    background-color: #1E1E2E;
}
QListWidget#sidebarNav::item:selected {
    background-color: #313244;
    border-left: 3px solid #89B4FA;
    color: #FFFFFF;
}
QListWidget#sidebarNav::item:disabled {
    color: #585B70;
}
"""


class SidebarTabs(QWidget):
    currentChanged = Signal(int)

    def __init__(self, parent=None, sidebar_width: int = 180):
        super().__init__(parent)
        self._nav = QListWidget()
        self._nav.setObjectName("sidebarNav")
        self._nav.setFixedWidth(sidebar_width)
        self._nav.setStyleSheet(SIDEBAR_STYLE)
        self._nav.setFocusPolicy(Qt.StrongFocus)
        self._stack = QStackedWidget()
        self._pages: list[QWidget] = []

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._nav)
        layout.addWidget(self._stack, 1)

        self._nav.currentRowChanged.connect(self._on_row_changed)

    # -- QTabWidget-compatible API -------------------------------------------
    def addTab(self, page: QWidget, title: str) -> int:
        index = len(self._pages)
        self._pages.append(page)
        self._stack.addWidget(page)
        item = QListWidgetItem(title)
        item.setData(Qt.UserRole, index)
        self._nav.addItem(item)
        if index == 0:
            self._nav.setCurrentRow(0)
        return index

    def count(self) -> int:
        return len(self._pages)

    def widget(self, index: int) -> QWidget | None:
        if 0 <= index < len(self._pages):
            return self._pages[index]
        return None

    def indexOf(self, page: QWidget) -> int:
        try:
            return self._pages.index(page)
        except ValueError:
            return -1

    def tabText(self, index: int) -> str:
        item = self._item(index)
        return item.text() if item is not None else ""

    def setTabText(self, index: int, text: str) -> None:
        item = self._item(index)
        if item is not None:
            item.setText(text)

    def setTabEnabled(self, index: int, enabled: bool) -> None:
        item = self._item(index)
        if item is None:
            return
        if enabled:
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        else:
            item.setFlags(Qt.NoItemFlags)
            if self._nav.currentRow() == self._nav.row(item):
                self._select_first_enabled(exclude=index)

    def isTabEnabled(self, index: int) -> bool:
        item = self._item(index)
        return bool(item is not None and item.flags() & Qt.ItemIsEnabled)

    def setTabToolTip(self, index: int, text: str) -> None:
        item = self._item(index)
        if item is not None:
            item.setToolTip(text)

    def tabToolTip(self, index: int) -> str:
        item = self._item(index)
        return item.toolTip() if item is not None else ""

    def currentIndex(self) -> int:
        return self._stack.currentIndex()

    def currentWidget(self) -> QWidget | None:
        return self._stack.currentWidget()

    def setCurrentIndex(self, index: int) -> None:
        item = self._item(index)
        if item is not None and self.isTabEnabled(index):
            self._nav.setCurrentRow(self._nav.row(item))

    def setCurrentWidget(self, page: QWidget) -> None:
        index = self.indexOf(page)
        if index >= 0:
            self.setCurrentIndex(index)

    # -- internals -------------------------------------------------------------
    def _item(self, index: int) -> QListWidgetItem | None:
        for row in range(self._nav.count()):
            item = self._nav.item(row)
            if item.data(Qt.UserRole) == index:
                return item
        return None

    def _on_row_changed(self, row: int) -> None:
        item = self._nav.item(row) if row >= 0 else None
        if item is None or not (item.flags() & Qt.ItemIsEnabled):
            return
        index = item.data(Qt.UserRole)
        self._stack.setCurrentIndex(index)
        self.currentChanged.emit(index)

    def _select_first_enabled(self, exclude: int) -> None:
        for index in range(len(self._pages)):
            if index != exclude and self.isTabEnabled(index):
                self.setCurrentIndex(index)
                return
