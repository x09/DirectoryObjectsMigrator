"""FreeIPA discovery, actionable migration preview and CSV export."""
from html import escape
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTableWidgetItem,
                            QPushButton, QTabWidget, QPlainTextEdit, QMessageBox)
from gui.migration_table import MigrationTable
from gui.preview_dialog import COLOR_CREATE, COLOR_EXISTS, COLOR_CONFLICT, COLOR_DEFERRED, COLOR_SKIPPED
from utils.i18n import _

COLORS = {'create': COLOR_CREATE, 'exists': COLOR_EXISTS, 'skip': COLOR_SKIPPED,
          'conflict': COLOR_CONFLICT, 'error': COLOR_CONFLICT,
          'ready': COLOR_CREATE, 'deferred': COLOR_DEFERRED, 'recreate': COLOR_DEFERRED}


def fill_row(table, index, texts, status, data=None):
    for col, value in enumerate(texts):
        item = QTableWidgetItem(value)
        item.setToolTip(value)
        item.setBackground(COLORS[status])
        if col == 0:
            item.setData(Qt.UserRole, data)
        table.setItem(index, col, item)


def reason_text(reason):
    # gettext('') returns catalogue metadata, not an empty UI message.
    if not reason:
        return ''
    for prefix in ('Destination identity already exists: ', 'Invalid destination account name: ',
                   'Destination CN exceeds 64 characters: ', 'Invalid RFC2307 value: '):
        if reason.startswith(prefix):
            return _(prefix) + reason[len(prefix):]
    return _(reason)


def remedy(row):
    reason = row.reason
    if row.action == 'recreate':
        return _("Recreation is included in this plan. Start Migration will create the new object and rebuild supported source links. Previous permissions are not restored automatically.")
    if row.recreation:
        return _("The tracked object is absent. Select Recreate deleted objects and confirm, then review the new plan. Recreation assigns a new SID/GUID and does not restore old permissions, passwords or destination-only memberships.")
    if row.action == 'conflict':
        return _("This object already exists or shares a target name/ID. Select the history database used for its previous migration. If it is an unrelated object, change the naming/data in the directories or exclude this source object. Matching names alone cannot confirm identity.")
    if 'password' in reason.lower():
        return _("Reset the password of the tracked destination user using domain administration tools, then analyze again. The application will not overwrite an existing password automatically.")
    if 'RFC2307' in reason:
        return _("Use the RFC2307 mode used for the original migration. Check the target schema and UID/GID values; existing attributes are not overwritten.")
    if 'primary group' in reason.lower():
        return _("Check the user's gidNumber and the corresponding group. With RFC2307 enabled, the primary group must also be included. Correct the source data or exclude the dependent user.")
    if 'read rights' in reason:
        return _("Grant the source account read access to the required attributes, or use an account with sufficient rights, then analyze again.")
    if 'ipaUniqueID' in reason or not row.source.name:
        return _("Correct the missing, ambiguous or duplicate source identity/name in FreeIPA. Such identity errors cannot be bypassed by accepting a same-named destination object.")
    if row.source.kind == 'user' and len(row.source.name) > 20 and 'Invalid destination account name' in reason:
        return _("Enable shortening of long logins in the FreeIPA connection settings and analyze again. Other invalid characters must be corrected in the source or the object excluded.")
    if row.action == 'error':
        return _("Check the reason and connection settings. Correct the source/target data or exclude this object, then analyze again.")
    if row.action == 'skip':
        return _("This object is excluded and does not block migration. References to excluded objects are skipped too.")
    return _("No action is required for this row. Use the context menu to export the table to CSV.")


class FreeIPADiscoveryDialog(QDialog):
    def __init__(self, snapshot, parent=None):
        super().__init__(parent)
        self.setWindowTitle(_("FreeIPA analysis"))
        self.resize(1000, 600)
        layout = QVBoxLayout(self)
        note = QLabel(_("Read-only discovery. Configure the destination to prepare a migration plan."))
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addWidget(QLabel(_("Eligible users: {users}; groups: {groups}; excluded or invalid: {skipped}").format(
            users=sum(o.kind == 'user' for o in snapshot.eligible),
            groups=sum(o.kind == 'group' for o in snapshot.eligible),
            skipped=len(snapshot.objects)-len(snapshot.eligible))))
        layout.addWidget(QLabel(_("User logins over 20 characters: {count}. Configure the destination to preview shortened names.").format(
            count=sum(o.kind == 'user' and len(o.name) > 20 for o in snapshot.objects))))
        self.table = MigrationTable(len(snapshot.objects), 4)
        self.table.setHorizontalHeaderLabels([_("Type"), _("Source DN"), 'ipaUniqueID', _("Reason")])
        for row, obj in enumerate(snapshot.objects):
            kind = _("User") if obj.kind == 'user' else _("Group")
            status = 'error' if obj.error else 'skip' if obj.reason else 'create'
            fill_row(self.table, row, (kind, obj.dn, obj.source_id, reason_text(obj.reason) if obj.reason else _("Eligible")), status)
        self.table.resizeColumnsToContents()
        layout.addWidget(self.table)
        close = QPushButton(_("Close"))
        close.clicked.connect(self.accept)
        layout.addWidget(close)


class FreeIPAPlanDialog(QDialog):
    EXCLUDE_AND_REANALYZE = 2
    OPEN_SETTINGS = 3
    CHOOSE_HISTORY = 4
    RECREATE_AND_REANALYZE = 5

    def __init__(self, plan, dry_run=False, parent=None, history_path=None):
        super().__init__(parent)
        self.excluded_dns = []
        self.requested_recreations = dict(plan.recreation_requests)
        self.setWindowTitle(_("FreeIPA migration plan"))
        self.resize(1180, 760)
        layout = QVBoxLayout(self)
        labels = {'create': _("Create"), 'exists': _("Exists"), 'skip': _("Skipped"),
                  'conflict': _("Conflict"), 'error': _("Error"), 'recreate': _("Recreate")}
        ink = {'create': '#28752c', 'exists': '#555555', 'skip': '#666666', 'conflict': '#b00020', 'error': '#b00020', 'recreate': '#956000'}
        summary = '; '.join('<span style="color:' + ink[action] + '"><b>' + escape(label) + ': ' +
                            str(sum(r.action == action for r in plan.rows)) + '</b></span>' for action, label in labels.items())
        layout.addWidget(QLabel(summary))
        if plan.login_statistics:
            self.login_summary = QLabel(_("Logins over 20 characters: {total}; eligible: {eligible}; new shortened names: {generated}; names retained from history: {retained}; suffix digits: {digits}.").format(**plan.login_statistics))
            self.login_summary.setWordWrap(True)
            layout.addWidget(self.login_summary)
        if history_path:
            history = QLabel(_("History database:") + ' ' + str(history_path))
            history.setTextFormat(Qt.PlainText)
            history.setTextInteractionFlags(Qt.TextSelectableByMouse)
            history.setWordWrap(True)
            layout.addWidget(history)
        note = QLabel(_("New users remain disabled. Existing objects are not overwritten. Missing memberships are added only to tracked objects."))
        note.setWordWrap(True)
        layout.addWidget(note)
        self.tabs = QTabWidget()
        self.table = MigrationTable(len(plan.rows), 5)
        self.table.setHorizontalHeaderLabels([_("Action"), _("Source DN"), _("Destination DN"), 'sAMAccountName', _("Reason")])
        for i, row in enumerate(plan.rows):
            fill_row(self.table, i, (labels[row.action], row.source.dn, row.target_dn,
                     str(row.attributes.get('sAMAccountName', '')), reason_text(row.reason)), row.action, row)
        self.table.setWordWrap(False)
        for column, width in enumerate((115, 230, 250, 185, 270)):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.tabs.addTab(self.table, _("Objects"))
        self.links_table = MigrationTable(len(plan.links), 4)
        self.links_table.setHorizontalHeaderLabels([_("Source DN"), _("Attribute"), _("Referenced DN"), _("State")])
        parents = {row.source.source_id: row.source.dn for row in plan.rows}
        states = {'ready': _("Ready"), 'skip': _("Skipped"), 'deferred': _("Deferred")}
        for i, link in enumerate(plan.links):
            fill_row(self.links_table, i, (parents[link.parent_id], link.attribute, link.source_dn,
                     states[link.state] + (': ' + reason_text(link.reason) if link.reason else '')), link.state)
        self.links_table.setWordWrap(False)
        for column, width in enumerate((280, 90, 280, 350)):
            self.links_table.setColumnWidth(column, width)
        self.links_table.horizontalHeader().setStretchLastSection(True)
        self.tabs.addTab(self.links_table, _("References"))
        warnings = [('', message) for message in plan.attribute_warnings]
        warnings.extend((row.source.dn, message) for row in plan.rows for message in row.attribute_warnings)
        self.attribute_table = MigrationTable(len(warnings), 2)
        self.attribute_table.setHorizontalHeaderLabels([_("Source DN"), _("Attribute warning")])
        self.attribute_table.setColumnWidth(0, 350)
        self.attribute_table.horizontalHeader().setStretchLastSection(True)
        for i, (dn, message) in enumerate(warnings):
            fill_row(self.attribute_table, i, (dn, message), 'deferred')
        self.tabs.addTab(self.attribute_table, _("Attribute warnings") + ' (' + str(len(warnings)) + ')')
        if warnings:
            warning_note = QLabel(_("Optional attribute warnings do not block creation. See Attribute warnings for fields that will be skipped."))
            warning_note.setWordWrap(True)
            layout.addWidget(warning_note)
        layout.addWidget(self.tabs)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(130)
        self.details.setPlaceholderText(_("Select a row to see the reason and suggested action. Right-click a table to export it to CSV."))
        layout.addWidget(self.details)
        actions = QHBoxLayout()
        self.exclude_btn = QPushButton(_("Exclude selected and analyze again"))
        self.exclude_btn.clicked.connect(self._exclude)
        self.exclude_btn.setEnabled(False)
        actions.addWidget(self.exclude_btn)
        history_btn = QPushButton(_("Use existing migration history…"))
        history_btn.clicked.connect(lambda: self.done(self.CHOOSE_HISTORY))
        actions.addWidget(history_btn)
        settings_btn = QPushButton(_("Connection Settings"))
        settings_btn.clicked.connect(lambda: self.done(self.OPEN_SETTINGS))
        actions.addWidget(settings_btn)
        layout.addLayout(actions)
        self.recreate_btn = QPushButton(_("Recreate deleted objects…"))
        self.recreate_btn.setEnabled(False)
        self.recreate_btn.clicked.connect(self._recreate)
        layout.addWidget(self.recreate_btn)
        if plan.blocked:
            hint = QLabel(_("Migration is blocked by errors/conflicts. Select a highlighted row for instructions, choose the correct history, or exclude supported objects and analyze again."))
            hint.setWordWrap(True)
            layout.addWidget(hint)
        self.proceed_btn = QPushButton(_("Start Dry Run") if dry_run else _("Start Migration"))
        self.proceed_btn.setEnabled(not plan.blocked)
        self.proceed_btn.clicked.connect(self.accept)
        layout.addWidget(self.proceed_btn)
        close = QPushButton(_("Close"))
        close.clicked.connect(self.reject)
        layout.addWidget(close)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.tabs.currentChanged.connect(self._selection_changed)
        first_problem = next((i for i, row in enumerate(plan.rows) if row.action in ('error', 'conflict')), None)
        if first_problem is not None:
            self.table.selectRow(first_problem)

    def selected_objects(self):
        return [self.table.item(index.row(), 0).data(Qt.UserRole)
                for index in self.table.selectionModel().selectedRows()]

    def _selection_changed(self, *args):
        rows = self.selected_objects() if self.tabs.currentIndex() == 0 else []
        # Missing/duplicate identities must be repaired in the source. Excluding
        # one duplicate must not let it inherit another object's GUID mapping.
        can_exclude = rows and all(row.source.source_id and row.source.name and
                                  'ipaUniqueID' not in row.reason for row in rows)
        self.exclude_btn.setEnabled(bool(can_exclude))
        self.recreate_btn.setEnabled(bool(rows) and all(row.recreation and row.action == 'error'
                                                      for row in rows))
        if rows:
            row = rows[0]
            self.details.setPlainText(row.source.dn + '\n' + row.target_dn + '\n' +
                                      reason_text(row.reason) + '\n\n' + remedy(row))
        else:
            self.details.clear()

    def _exclude(self):
        if not self.exclude_btn.isEnabled():
            return
        self.excluded_dns = [row.source.dn for row in self.selected_objects()]
        self.done(self.EXCLUDE_AND_REANALYZE)

    def _recreate(self):
        if not self.recreate_btn.isEnabled():
            return
        rows = self.selected_objects()
        question = QMessageBox(self)
        question.setIcon(QMessageBox.Warning)
        question.setWindowTitle(_("Recreate deleted objects"))
        question.setText(_("Recreate the selected deleted objects: {count}?").format(count=len(rows)))
        question.setInformativeText(_("New objects will have new SID/GUID values. Previous permissions, passwords and destination-only memberships will not be restored. Users will be disabled with new passwords. Supported source memberships and manager links will be rebuilt. This only prepares a new plan; creation starts after Start Migration."))
        question.setDetailedText('\n\n'.join(row.source.dn + '\n' + row.target_dn +
                                 '\nGUID: ' + row.recreation['old_guid'] for row in rows))
        question.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        question.setDefaultButton(QMessageBox.No)
        question.button(QMessageBox.Yes).setText(_("Recreate"))
        question.button(QMessageBox.No).setText(_("Cancel"))
        # Qt's system catalogue is not guaranteed to be installed alongside ours.
        for button in question.buttons():
            if question.buttonRole(button) == QMessageBox.ActionRole:
                button.setText(_("Details…"))
                button.clicked.connect(lambda checked=False, button=button: button.setText(_("Details…")))
        if question.exec_() != QMessageBox.Yes:
            return
        self.requested_recreations.update({row.source.source_id: dict(row.recreation) for row in rows})
        self.done(self.RECREATE_AND_REANALYZE)
