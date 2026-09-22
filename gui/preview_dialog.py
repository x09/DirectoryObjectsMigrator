"""
Preview Dialog
Shows the analysis result and the concrete migration plan before anything runs.

The plan is computed by Migrator.build_plan(), which consults the migration
database and the destination directory. That is what makes the preview accurate
on a repeat run: objects already migrated appear under EXISTS rather than being
promised as new creations.
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QGroupBox, QTextEdit, QTabWidget, QWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from core.analyzer import AnalysisResult
from utils.i18n import _
from config import settings

# Row background colours, mirroring the log status vocabulary
COLOR_CREATE = QColor(200, 230, 201)    # green
COLOR_EXISTS = QColor(225, 225, 225)    # grey
COLOR_CONFLICT = QColor(255, 205, 210)  # red
COLOR_DEFERRED = QColor(255, 224, 178)  # orange
COLOR_SKIPPED = QColor(245, 245, 245)   # light grey
COLOR_NEUTRAL = QColor(255, 249, 196)   # yellow

TYPE_LABELS = {
    settings.OBJECT_TYPE_OU: 'Organizational Units',
    settings.OBJECT_TYPE_USER: 'Users',
    settings.OBJECT_TYPE_GROUP: 'Groups',
    settings.OBJECT_TYPE_CONTACT: 'Contacts',
}


class PreviewDialog(QDialog):
    """Dialog showing the migration plan"""

    def __init__(self, analysis_result: AnalysisResult, plan=None, dry_run=False,
                 parent=None):
        """
        Args:
            analysis_result: Result of the source scan
            plan: MigrationPlan from Migrator.build_plan(). When omitted the
                dialog degrades to showing source counts only, and says so.
            dry_run: Whether the run that follows will be a simulation
        """
        super().__init__(parent)
        self.analysis_result = analysis_result
        self.plan = plan
        self.dry_run = dry_run

        self.setWindowTitle(_("Migration Preview"))
        self.setMinimumSize(900, 680)
        self.setModal(True)

        self._init_ui()
        self._populate()

    # ---------------------------------------------------------------- UI ---

    def _init_ui(self):
        layout = QVBoxLayout(self)

        title = QLabel(_("Migration Preview"))
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 6px;")
        layout.addWidget(title)

        summary_group = QGroupBox(_("Summary"))
        summary_layout = QVBoxLayout()
        self.summary_label = QLabel()
        self.summary_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.summary_label.setWordWrap(True)
        summary_layout.addWidget(self.summary_label)
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)

        self.tabs = QTabWidget()
        self.plan_table = self._make_table(
            [_("Action"), _("Type"), _("Source DN"), _("Destination DN")])
        self.tabs.addTab(self._wrap(self.plan_table), _("Planned actions"))

        self.deferred_table = self._make_table(
            [_("Object"), _("Attribute"), _("Referenced object"), _("Status")])
        self.tabs.addTab(self._wrap(self.deferred_table), _("Deferred references"))

        self.counts_table = self._make_table([_("Object Type"), _("Count")])
        self.tabs.addTab(self._wrap(self.counts_table), _("Objects found"))

        layout.addWidget(self.tabs)

        notes_group = QGroupBox(_("Notes"))
        notes_layout = QVBoxLayout()
        self.notes_text = QTextEdit()
        self.notes_text.setReadOnly(True)
        self.notes_text.setMaximumHeight(110)
        notes_layout.addWidget(self.notes_text)
        notes_group.setLayout(notes_layout)
        layout.addWidget(notes_group)

        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.proceed_btn = QPushButton(
            _("Start Dry Run") if self.dry_run else _("Start Migration"))
        self.proceed_btn.clicked.connect(self.accept)
        self.proceed_btn.setStyleSheet(
            "background-color: #4CAF50; color: white; padding: 8px 16px;")
        button_layout.addWidget(self.proceed_btn)

        self.cancel_btn = QPushButton(_("Cancel"))
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

    @staticmethod
    def _make_table(headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    @staticmethod
    def _wrap(widget) -> QWidget:
        holder = QWidget()
        holder_layout = QVBoxLayout(holder)
        holder_layout.setContentsMargins(0, 0, 0, 0)
        holder_layout.addWidget(widget)
        return holder

    # ----------------------------------------------------------- populate ---

    def _populate(self):
        self._populate_counts()

        if self.plan is None:
            self._populate_without_plan()
            return

        self._populate_summary()
        self._populate_plan_table()
        self._populate_deferred_table()
        self._populate_notes()

    def _populate_summary(self):
        s = self.plan.summary()
        mode = _("Dry run - nothing will be written") if self.dry_run else _("Live migration")

        # Show only truly deferred references (not resolvable in this run)
        truly_deferred = s['deferred'] - s['deferred_resolvable_now']

        self.summary_label.setText(
            f"<b>{_('Source')}:</b> {self.plan.base_dn}<br>"
            f"<b>{_('Destination')}:</b> {self.plan.dest_base_dn}<br>"
            f"<b>{_('Mode')}:</b> {mode}<br><br>"
            f"<b style='color:#2E7D32;'>{_('CREATE')}: {s['create']}</b> &nbsp;|&nbsp; "
            f"<b style='color:#616161;'>{_('EXISTS')}: {s['exists']}</b> &nbsp;|&nbsp; "
            f"<b style='color:#C62828;'>{_('CONFLICT')}: {s['conflict']}</b> &nbsp;|&nbsp; "
            f"<b style='color:#757575;'>{_('SKIPPED')}: {s['skipped']}</b> &nbsp;|&nbsp; "
            f"<b style='color:#EF6C00;'>{_('DEFERRED')}: {truly_deferred}</b>"
            + (f" &nbsp;|&nbsp; <b style='color:#C62828;'>{_('ERROR')}: {s['errors']}</b>"
               if s['errors'] else "")
        )

    def _populate_plan_table(self):
        rows = (
            [('CREATE', COLOR_CREATE, item) for item in self.plan.create] +
            [('CONFLICT', COLOR_CONFLICT, item) for item in self.plan.conflict] +
            [('EXISTS', COLOR_EXISTS, item) for item in self.plan.exists] +
            [('SKIPPED', COLOR_SKIPPED, item) for item in self.plan.skipped] +
            [('ERROR', COLOR_CONFLICT, item) for item in self.plan.errors]
        )

        self.plan_table.setRowCount(len(rows))
        for row, (action, color, (source_dn, dest_dn, object_type)) in enumerate(rows):
            cells = [_(action), _(TYPE_LABELS.get(object_type, object_type)),
                     source_dn, dest_dn]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setBackground(color)
                self.plan_table.setItem(row, col, item)

        self.plan_table.resizeColumnsToContents()
        self.tabs.setTabText(0, f"{_('Planned actions')} ({len(rows)})")

    def _populate_deferred_table(self):
        # Show only references that will remain deferred after this run.
        # Resolvable references are handled during migration and don't need to be
        # tracked separately in the UI.
        truly_deferred = [
            (parent_dn, attr, ref_dn, resolvable)
            for parent_dn, attr, ref_dn, resolvable in self.plan.deferred
            if not resolvable
        ]

        self.deferred_table.setRowCount(len(truly_deferred))

        for row, (parent_dn, attr, ref_dn, resolvable) in enumerate(truly_deferred):
            status = _("Target not migrated yet")
            cells = [parent_dn, attr, ref_dn, status]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 3:
                    item.setBackground(COLOR_DEFERRED)
                self.deferred_table.setItem(row, col, item)

        self.deferred_table.resizeColumnsToContents()
        self.tabs.setTabText(1, f"{_('Deferred references')} ({len(truly_deferred)})")

    def _populate_counts(self):
        counts = self.analysis_result.counts_by_type
        rows = [
            (_(TYPE_LABELS[settings.OBJECT_TYPE_OU]), counts.get(settings.OBJECT_TYPE_OU, 0), False),
            (_(TYPE_LABELS[settings.OBJECT_TYPE_USER]), counts.get(settings.OBJECT_TYPE_USER, 0), False),
            (_(TYPE_LABELS[settings.OBJECT_TYPE_GROUP]), counts.get(settings.OBJECT_TYPE_GROUP, 0), False),
            (_(TYPE_LABELS[settings.OBJECT_TYPE_CONTACT]), counts.get(settings.OBJECT_TYPE_CONTACT, 0), False),
            (_("Unsupported"), counts.get('unsupported', 0), True),
            (_("Ignored"), counts.get('ignored', 0), True),
        ]

        self.counts_table.setRowCount(len(rows))
        for row, (label, count, neutral) in enumerate(rows):
            self.counts_table.setItem(row, 0, QTableWidgetItem(label))
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            if count:
                count_item.setBackground(COLOR_NEUTRAL if neutral else COLOR_CREATE)
            self.counts_table.setItem(row, 1, count_item)

        self.counts_table.resizeColumnsToContents()

    def _populate_notes(self):
        s = self.plan.summary()
        notes = []

        if s['conflict']:
            notes.append(
                f"<b style='color:#C62828;'>{s['conflict']} {_('CONFLICT')}</b>: " +
                _("these objects already exist in the destination but are not tracked "
                  "in the migration database. They will NOT be overwritten."))

        if s['errors']:
            notes.append(
                f"<b style='color:#C62828;'>{s['errors']} {_('ERROR')}</b>: " +
                _("could not be classified (missing objectGUID or unreadable "
                  "destination). They will be skipped and logged."))

        if s['deferred']:
            resolvable = s['deferred_resolvable_now']
            notes.append(
                f"<b style='color:#EF6C00;'>{s['deferred']} {_('DEFERRED')}</b>: " +
                _("references pointing outside the migration scope.") +
                f" {resolvable} " + _("can be added now; the rest need their target "
                                      "migrated first, then re-run this DN."))

        if not self.dry_run and s['create']:
            notes.append(_("Users are created disabled with a generated password. "
                           "Set final passwords and enable the accounts afterwards."))

        if self.dry_run:
            notes.append(_("Dry run: the destination directory will not be modified."))

        if not s['create']:
            notes.insert(0, self._empty_plan_note(s))

        self.notes_text.setHtml("<br><br>".join(n for n in notes if n))

    def _empty_plan_note(self, summary) -> str:
        """
        Explain why there is nothing to create.

        A single "everything is already migrated" message used to cover every case,
        which actively misled: when a scope was filtered out by the ignore rules the
        tool claimed the objects had already been transferred. Each cause now gets
        its own explanation.
        """
        counts = self.analysis_result.counts_by_type
        ignored = counts.get('ignored', 0)
        unsupported = counts.get('unsupported', 0)

        if summary['exists']:
            # Genuinely idempotent: the objects are tracked in the migration database
            return ("<b>" + _("Nothing to create") + "</b>: " +
                    _("every object in this scope has already been migrated."))

        if self.analysis_result.total_objects == 0:
            return ("<b>" + _("Nothing found") + "</b>: " +
                    _("the specified DN contains no objects. Check the Base DN."))

        if summary['conflict'] and not ignored and not unsupported:
            return ("<b>" + _("Nothing to create") + "</b>: " +
                    _("every object in this scope is in conflict, see above."))

        if ignored or unsupported:
            parts = []
            if ignored:
                parts.append(f"{ignored} " + _("ignored"))
            if unsupported:
                parts.append(f"{unsupported} " + _("unsupported"))
            return ("<b>" + _("Nothing to create") + "</b>: " +
                    _("all objects found were filtered out") +
                    f" ({', '.join(parts)}). " +
                    _("Built-in containers and computer accounts are skipped by "
                      "design; see the 'Objects found' tab."))

        return ("<b>" + _("Nothing to create") + "</b>: " +
                _("no object in this scope is eligible for migration."))

    def _populate_without_plan(self):
        """Fallback when no plan was supplied (source counts only)."""
        result = self.analysis_result
        self.summary_label.setText(
            f"<b>{_('Base DN')}:</b> {result.base_dn}<br>"
            f"<b>{_('Total objects')}:</b> {result.total_objects}"
        )
        self.tabs.setCurrentIndex(2)
        self.plan_table.setRowCount(0)
        self.deferred_table.setRowCount(0)
        self.notes_text.setHtml(
            "<b>" + _("Destination was not checked") + "</b><br>" +
            _("These are source counts only. Existing objects and conflicts are "
              "not reflected here.")
        )


if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication
    from core.migrator import MigrationPlan

    app = QApplication(sys.argv)

    result = AnalysisResult(base_dn="OU=Level2,OU=Level1,DC=source,DC=alt")
    result.counts_by_type = {
        settings.OBJECT_TYPE_OU: 2,
        settings.OBJECT_TYPE_USER: 3,
        settings.OBJECT_TYPE_GROUP: 1,
        settings.OBJECT_TYPE_CONTACT: 0,
        'unsupported': 0,
        'ignored': 1,
    }
    result.total_objects = 7

    demo = MigrationPlan("OU=Level2,OU=Level1,DC=source,DC=alt",
                         "OU=Level2,OU=Level1,DC=dest,DC=alt")
    demo.create = [
        ("CN=user1,OU=Level2,OU=Level1,DC=source,DC=alt",
         "CN=user1,OU=Level2,OU=Level1,DC=dest,DC=alt", settings.OBJECT_TYPE_USER),
        ("CN=group1,OU=Level2,OU=Level1,DC=source,DC=alt",
         "CN=group1,OU=Level2,OU=Level1,DC=dest,DC=alt", settings.OBJECT_TYPE_GROUP),
    ]
    demo.exists = [
        ("CN=user2,OU=Level2,OU=Level1,DC=source,DC=alt",
         "CN=user2,OU=Level2,OU=Level1,DC=dest,DC=alt", settings.OBJECT_TYPE_USER),
    ]
    demo.conflict = [
        ("CN=user4,OU=Level2,OU=Level1,DC=source,DC=alt",
         "CN=user4,OU=Level2,OU=Level1,DC=dest,DC=alt", settings.OBJECT_TYPE_USER),
    ]
    demo.deferred = [
        ("CN=group1,OU=Level2,OU=Level1,DC=source,DC=alt", "member",
         "CN=user5,OU=Level5,DC=source,DC=alt", True),
        ("CN=group1,OU=Level2,OU=Level1,DC=source,DC=alt", "member",
         "CN=user6,OU=Level6,DC=source,DC=alt", False),
    ]
    demo.ignored_count = 1

    dialog = PreviewDialog(result, plan=demo)
    dialog.show()
    sys.exit(app.exec_())
