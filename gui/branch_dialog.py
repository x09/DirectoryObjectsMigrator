"""Single-branch source directory browser with lazy, read-only LDAP queries."""
from queue import Queue, Empty

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem,
    QAbstractItemView, QDialogButtonBox, QPushButton, QStyle, QProgressBar,
)

from core.ldap_connector import LDAPConnector, LDAPConnectionError
from utils.i18n import _


class BranchLoader(QThread):
    """Own the connection entirely on this thread; serialize branch requests."""
    loaded = pyqtSignal(str, object, str)
    connection_failed = pyqtSignal()

    def __init__(self, connection_params, parent=None, connector_factory=LDAPConnector):
        super().__init__(parent)
        self.params = dict(connection_params)
        self.connector_factory = connector_factory
        self.requests = Queue()

    def load(self, dn):
        self.requests.put(dn)

    def run(self):
        connector = None
        try:
            while not self.isInterruptionRequested():
                try:
                    dn = self.requests.get(timeout=0.1)
                except Empty:
                    continue
                try:
                    if connector is None:
                        connector = self.connector_factory(**self.params)
                        connector.connect(retry_count=1)
                        if connector.get_object_by_dn(connector.domain_dn, ['objectClass']) is None:
                            raise LDAPConnectionError('Cannot read the source domain root')
                    children = connector.list_child_containers(dn, self.isInterruptionRequested)
                    if not self.isInterruptionRequested():
                        self.loaded.emit(dn, children, '')
                except Exception as exc:
                    if isinstance(exc, LDAPConnectionError):
                        self.connection_failed.emit()
                    if connector is not None:
                        connector.disconnect()
                        connector = None
                    if not self.isInterruptionRequested():
                        self.loaded.emit(dn, [], str(exc))
        finally:
            if connector is not None:
                connector.disconnect()
            self.params.clear()


class BranchDialog(QDialog):
    """Return one server-supplied DN; all widgets are touched on the GUI thread."""
    connection_failed = pyqtSignal()

    def __init__(self, connection_params, parent=None, connector_factory=LDAPConnector):
        super().__init__(parent)
        self.setWindowTitle(_("Select migration branch"))
        self.resize(720, 520)
        self.selected_dn = None
        self._closing_result = None
        self._pending = set()
        self._items = {}
        self._states = {}
        self.domain_dn = ','.join('DC=' + part for part in connection_params['domain'].split('.'))

        layout = QVBoxLayout(self)
        description = QLabel(_("Select one branch of the source domain. All nested objects are included."))
        description.setWordWrap(True)
        layout.addWidget(description)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([_("Branch"), _("Type")])
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setColumnWidth(0, 470)
        self.tree.itemExpanded.connect(self._expand)
        self.tree.itemSelectionChanged.connect(self._selection_changed)
        layout.addWidget(self.tree)
        self.dn_label = QLabel(_("Selected DN:") + ' —')
        self.dn_label.setWordWrap(True)
        self.dn_label.setTextFormat(Qt.PlainText)
        self.dn_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.dn_label)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        layout.addWidget(self.status)
        self.loading_indicator = QProgressBar()
        self.loading_indicator.setRange(0, 0)  # Indeterminate: LDAP reports no total.
        self.loading_indicator.setTextVisible(False)
        self.loading_indicator.setAccessibleName(_("Loading branch…"))
        self.loading_indicator.setFixedHeight(14)
        self.loading_indicator.hide()
        layout.addWidget(self.loading_indicator)
        note = QLabel(_("Only objects visible to your account are shown. Migration exclusions still apply."))
        note.setWordWrap(True)
        layout.addWidget(note)
        row = QHBoxLayout()
        self.refresh_btn = QPushButton(_("Refresh tree"))
        self.refresh_btn.clicked.connect(self._refresh)
        row.addWidget(self.refresh_btn)
        row.addStretch()
        self.buttons = QDialogButtonBox()
        self.select_btn = self.buttons.addButton(_("Select"), QDialogButtonBox.AcceptRole)
        self.buttons.addButton(_("Cancel"), QDialogButtonBox.RejectRole)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        row.addWidget(self.buttons)
        layout.addLayout(row)
        self.select_btn.setEnabled(False)
        self.loader = BranchLoader(connection_params, self, connector_factory)
        self.loader.loaded.connect(self._loaded)
        self.loader.connection_failed.connect(self.connection_failed)
        self.loader.finished.connect(self._stopped)
        self.loader.start()
        self._refresh()

    def _add_item(self, parent, dn, name, kind):
        item = QTreeWidgetItem(parent, [name, kind])
        item.setData(0, Qt.UserRole, dn)
        item.setData(0, Qt.UserRole + 1, name)
        item.setToolTip(0, dn)
        item.setIcon(0, self.style().standardIcon(QStyle.SP_DirIcon))
        item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        self._items[dn] = item
        self._states[dn] = 'new'
        return item

    def _refresh(self):
        if self._pending or self._closing_result is not None:
            return
        self.tree.clear()
        self._items.clear()
        self._states.clear()
        root = self._add_item(self.tree, self.domain_dn, self.domain_dn, _("Domain"))
        root.setFlags(root.flags() & ~Qt.ItemIsSelectable)
        root.setExpanded(True)

    def _expand(self, item):
        dn = item.data(0, Qt.UserRole)
        if self._states.get(dn) not in ('new', 'error') or self._closing_result is not None:
            return
        self._states[dn] = 'loading'
        self._pending.add(dn)
        item.setText(0, item.data(0, Qt.UserRole + 1) + ' — ' + _("Loading branch…"))
        self.loading_indicator.show()
        self.refresh_btn.setEnabled(False)
        self.status.setText(_("Loading branch…") + '\n' + dn)
        self.loader.load(dn)

    def _loaded(self, dn, children, error):
        self._pending.discard(dn)
        if self._closing_result is not None:
            return
        item = self._items[dn]
        item.setText(0, item.data(0, Qt.UserRole + 1))
        self.loading_indicator.setVisible(bool(self._pending))
        self.refresh_btn.setEnabled(not self._pending)
        if error:
            self._states[dn] = 'error'
            item.setExpanded(False)
            self.status.setText(_("Could not load branch. Expand it again to retry, or refresh the tree.") + '\n' + error)
            item.setToolTip(0, dn + '\n' + error)
            return
        self._states[dn] = 'loaded'
        item.setFlags(item.flags() | Qt.ItemIsSelectable)
        item.setToolTip(0, dn)
        for child in children:
            self._add_item(item, child['dn'], child['name'],
                           _("Organizational unit") if child['kind'] == 'ou' else _("Container"))
        if not children:
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicatorWhenChildless)
        if self._pending:
            self.status.setText(_("Loading branch…") + '\n' + '\n'.join(sorted(self._pending)))
        else:
            self.status.setText(_("Select a branch, then click Select."))
        self._selection_changed()

    def _selection_changed(self):
        items = self.tree.selectedItems()
        dn = items[0].data(0, Qt.UserRole) if items else None
        self.dn_label.setText(_("Selected DN:") + ' ' + (dn or '—'))
        self.select_btn.setEnabled(bool(dn) and self._closing_result is None)

    def done(self, result):
        # Never destroy a running QThread or block the GUI while LDAP times out.
        if self._closing_result is not None:
            return
        if result == QDialog.Accepted:
            items = self.tree.selectedItems()
            if not items:
                return
            self.selected_dn = items[0].data(0, Qt.UserRole)
        self._closing_result = result
        self.tree.setEnabled(False)
        self.buttons.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        self.loading_indicator.show()
        self.status.setText(_("Closing connection… Waiting for the current LDAP request to finish."))
        self.loader.requestInterruption()
        if not self.loader.isRunning():
            self._stopped()

    def _stopped(self):
        if self._closing_result is not None:
            self.loading_indicator.hide()
            super().done(self._closing_result)

    def closeEvent(self, event):
        self.reject()
        event.ignore()
