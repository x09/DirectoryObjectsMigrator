"""
Main Window
Main application window
"""
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QTextEdit, QGroupBox, QMenuBar, QMenu, QAction,
    QStatusBar, QMessageBox, QFileDialog, QInputDialog, QDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QTextCursor

from gui.analysis_dialog import AnalysisDialog, AnalysisWorker
from gui.connection_dialog import ConnectionDialog
from gui.branch_dialog import BranchDialog
from gui.preview_dialog import PreviewDialog
from gui.progress_window import ProgressWindow, completion_title

from core.sources import source_connector_class
from core.ldap_connector import LDAPConnector, LDAPConnectionError
from core.migrator import Migrator, MigrationResult
from core.analyzer import AnalysisResult
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger
from utils.config_manager import ConfigManager
from utils.report_generator import ReportGenerator
from utils.i18n import _, get_language, get_available_languages
from config import settings

import sys
import webbrowser
from pathlib import Path


class MigrationWorker(QThread):
    """
    Worker thread for migration.

    Every GUI update must travel through the signals below. Qt widgets may only be
    touched from the GUI thread; calling them directly from this thread corrupts
    Qt's internal state and segfaults. The migrator is assigned after construction
    so that its callbacks can emit this worker's signals.
    """

    progress_update = pyqtSignal(int, str)          # percent, message
    log_message = pyqtSignal(str, str)              # level, message
    migration_complete = pyqtSignal(bool, object)   # success, result

    def __init__(self, base_dn: str, parent=None):
        super().__init__(parent)
        self.base_dn = base_dn
        self.migrator = None

    def emit_progress(self, percent: int, message: str):
        """Progress callback handed to the Migrator (safe to call off-thread)."""
        self.progress_update.emit(int(percent), str(message))

    def emit_log(self, level: str, message: str):
        """Log callback handed to the MigrationLogger (safe to call off-thread)."""
        self.log_message.emit(str(level), str(message))

    def run(self):
        """Run migration in background thread"""
        if self.migrator is None:
            self.log_message.emit('CRITICAL', 'Migrator was not configured')
            self.migration_complete.emit(False, None)
            return

        try:
            result = self.migrator.migrate(self.base_dn)
            self.migration_complete.emit(result.success, result)
        except Exception as e:
            self.log_message.emit('CRITICAL', f"Migration failed: {e}")
            self.migration_complete.emit(False, None)


class FreeIPAMigrationWorker(MigrationWorker):
    def __init__(self, operation, parent=None):
        super().__init__('', parent)
        self.operation = operation
        self.cancelled = False

    def cancel(self):
        self.cancelled = True
        if self.migrator:
            self.migrator.cancel()

    def run(self):
        try:
            result = self.operation(self)
            self.migration_complete.emit(result.success, result)
        except Exception as exc:
            result = MigrationResult(status=settings.RUN_STATUS_FAILED,
                                     errors_count=1, failure_message=str(exc))
            self.migration_complete.emit(False, result)


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("Directory Objects Migrator"))
        self.setMinimumSize(1000, 700)
        self.setWindowIcon(self._load_app_icon())

        # Configuration
        self.config_manager = ConfigManager()

        # Passwords are kept in memory for the lifetime of this window only.
        # They are deliberately never written to the INI file.
        self._session_passwords = {'source': None, 'dest': None}

        # Connections
        self.source_conn = None
        self.dest_conn = None
        self.migration_db = None
        self.logger = None
        self.migrator = None

        # Worker thread
        self.migration_worker = None

        # Analysis result and the plan derived from it
        self.analysis_result = None
        self.migration_plan = None
        self.last_run_id = None

        # The language must already be active before any widget is built, which
        # main.py does at startup. Re-applying it here would be too late for this
        # window's own labels and, worse, would reset the active language for every
        # dialog created afterwards -- that is why dialogs used to stay English.
        self._init_ui()
        self._check_connections()

    def _init_ui(self):
        """Initialize UI"""
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Menu bar
        self._create_menu_bar()

        # Connection status
        status_group = QGroupBox(_("Connection Status"))
        status_layout = QHBoxLayout()

        self.source_status = QLabel(_("Source:") + " " + _("Not connected"))
        self.source_status.setStyleSheet("color: red;")
        status_layout.addWidget(self.source_status)

        status_layout.addStretch()

        self.dest_status = QLabel(_("Destination:") + " " + _("Not connected"))
        self.dest_status.setStyleSheet("color: red;")
        status_layout.addWidget(self.dest_status)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        # Migration settings
        settings_group = QGroupBox(_("Migration Settings"))
        settings_layout = QVBoxLayout()

        # Base DN
        self.base_dn_row = QWidget()
        base_dn_layout = QHBoxLayout(self.base_dn_row)
        base_dn_layout.setContentsMargins(0, 0, 0, 0)
        base_dn_layout.addWidget(QLabel(_("Base DN for Migration") + ":"))
        self.base_dn_input = QLineEdit()
        self.base_dn_input.setPlaceholderText("OU=Users,DC=domain,DC=alt")
        last_dn = self.config_manager.get_last_base_dn()
        if last_dn:
            self.base_dn_input.setText(last_dn)
        base_dn_layout.addWidget(self.base_dn_input)
        self.browse_base_dn_btn = QPushButton(_("Choose…"))
        self.browse_base_dn_btn.clicked.connect(self._browse_base_dn)
        base_dn_layout.addWidget(self.browse_base_dn_btn)
        self.base_dn_input.textChanged.connect(self._invalidate_analysis)
        settings_layout.addWidget(self.base_dn_row)
        self.freeipa_scope_label = QLabel(_("FreeIPA: users and groups from the accounts tree. Destination containers are configured in connection settings."))
        self.freeipa_scope_label.setWordWrap(True)
        settings_layout.addWidget(self.freeipa_scope_label)

        # Options
        options_layout = QHBoxLayout()
        self.dry_run_checkbox = QCheckBox(_("Dry Run Mode") + " (" + _("simulation without creating objects") + ")")
        self.dry_run_checkbox.setChecked(settings.DEFAULT_DRY_RUN)
        options_layout.addWidget(self.dry_run_checkbox)
        options_layout.addStretch()
        settings_layout.addLayout(options_layout)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Action buttons
        button_layout = QHBoxLayout()

        self.analyze_btn = QPushButton(_("Analyze"))
        self.analyze_btn.clicked.connect(self._analyze)
        self.analyze_btn.setEnabled(False)
        button_layout.addWidget(self.analyze_btn)

        self.migrate_btn = QPushButton(_("Start Migration"))
        self.migrate_btn.clicked.connect(self._start_migration)
        self.migrate_btn.setEnabled(False)
        # Green when enabled, grey when disabled (analysis not yet run)
        self.migrate_btn.setStyleSheet("""
            QPushButton:enabled {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
                padding: 8px 16px;
            }
        """)
        button_layout.addWidget(self.migrate_btn)

        button_layout.addStretch()

        self.report_btn = QPushButton(_("Generate Report"))
        self.report_btn.clicked.connect(self._generate_report)
        self.report_btn.setEnabled(False)
        button_layout.addWidget(self.report_btn)

        layout.addLayout(button_layout)

        # Log viewer
        log_group = QGroupBox(_("Log"))
        log_layout = QVBoxLayout()

        # Toolbar above the log text
        log_toolbar = QHBoxLayout()
        log_toolbar.addStretch()
        self.clear_log_btn = QPushButton(_("Clear Log"))
        self.clear_log_btn.clicked.connect(self._clear_log)
        log_toolbar.addWidget(self.clear_log_btn)
        log_layout.addLayout(log_toolbar)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("font-family: monospace; font-size: 9pt;")
        log_layout.addWidget(self.log_text)

        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage(_("Ready"))

    def _create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu(_("File"))

        settings_action = QAction(_("Settings"), self)
        settings_action.triggered.connect(self._open_settings)
        file_menu.addAction(settings_action)

        file_menu.addSeparator()

        exit_action = QAction(_("Exit"), self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Language menu
        lang_menu = menubar.addMenu(_("Language"))

        for lang_code in get_available_languages():
            lang_name = "English" if lang_code == "en" else "Русский"
            lang_action = QAction(lang_name, self)
            lang_action.setData(lang_code)
            lang_action.triggered.connect(lambda checked, code=lang_code: self._change_language(code))
            if lang_code == get_language():
                lang_action.setCheckable(True)
                lang_action.setChecked(True)
            lang_menu.addAction(lang_action)

        # Help menu
        help_menu = menubar.addMenu(_("Help"))

        about_action = QAction(_("About"), self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _open_settings(self):
        """Open settings dialog"""
        previous_database = self.config_manager.get_database_path()
        previous_mappings = self.config_manager.get_freeipa_mappings()
        previous_configs = {
            'source': self.config_manager.get_source_dc_config(),
            'dest': self.config_manager.get_dest_dc_config(),
        }
        dialog = ConnectionDialog(self.config_manager, self)
        dialog.connections_saved.connect(self._check_connections)
        dialog.database_reset.connect(self._on_database_reset)

        if dialog.exec_() == ConnectionDialog.Accepted:
            if self.config_manager.get_freeipa_mappings() != previous_mappings:
                self._invalidate_analysis()
            if self.config_manager.get_database_path() != previous_database:
                self._history_changed()
            for dc_type, current in (
                ('source', self.config_manager.get_source_dc_config()),
                ('dest', self.config_manager.get_dest_dc_config()),
            ):
                if current != previous_configs[dc_type]:
                    self._session_passwords[dc_type] = None
                    conn = self.source_conn if dc_type == 'source' else self.dest_conn
                    if conn:
                        conn.disconnect()
                    if dc_type == 'source':
                        self.source_conn = None
                    else:
                        self.dest_conn = None
                    self._invalidate_analysis()
            # Adopt any passwords typed in the dialog for this session, so the user
            # is not asked again. They are still never written to the INI file.
            self._cache_passwords_from_dialog(dialog)

        self._check_connections()

    def _on_database_reset(self):
        """
        React to the migration history being cleared.

        The analysis and plan classified objects against the old database contents,
        so both are now wrong and must be recomputed. The report button is disabled
        too, because the run it referred to no longer exists.
        """
        self.analysis_result = None
        self.migration_plan = None
        self.last_run_id = None
        self.migrate_btn.setEnabled(False)
        self.report_btn.setEnabled(False)

        # Drop our own handle so the next action opens the reset database afresh
        if self.migration_db:
            self.migration_db.close()
            self.migration_db = None

        self._append_log('WARNING', 'Migration database was reset; run Analyze again')
        self.statusBar.showMessage(_("Migration database was reset"))

    def _cache_passwords_from_dialog(self, dialog: ConnectionDialog):
        """
        Store passwords entered in the connection dialog into the session cache.

        Changing a host/domain/username invalidates whatever password we held for
        that DC, and drops the open connection so the next action re-authenticates.
        """
        pairs = (
            ('source', dialog.get_source_connection_params()),
            ('dest', dialog.get_dest_connection_params()),
        )

        for dc_type, params in pairs:
            password = params.get('password')
            if password:
                self._session_passwords[dc_type] = password

            conn = self.source_conn if dc_type == 'source' else self.dest_conn
            if conn and (conn.host != params.get('host')
                         or conn.domain != params.get('domain')
                         or conn.username != params.get('username')):
                conn.disconnect()
                if dc_type == 'source':
                    self.source_conn = None
                else:
                    self.dest_conn = None

                # Either endpoint changing invalidates the analysis and the plan:
                # the plan records destination DNs and was classified against the
                # old connection.
                self.analysis_result = None
                self.migration_plan = None
                self.migrate_btn.setEnabled(False)

    def _change_language(self, lang_code: str):
        """
        Persist the chosen language and restart.

        A restart is used rather than retranslating in place: Qt widgets take their
        text at construction time, so every label, menu and dialog would have to be
        rebuilt. Saving the choice and re-executing is simpler and cannot leave the
        window half-translated.
        """
        if lang_code == self.config_manager.get_language():
            return

        reply = QMessageBox.question(
            self,
            _("Change Language"),
            _("Language will be changed after application restart. Restart now?"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        # Save regardless, so the choice takes effect on the next manual start
        self.config_manager.set_language(lang_code)

        if reply == QMessageBox.Yes:
            if self.migration_worker and self.migration_worker.isRunning():
                QMessageBox.warning(
                    self, _("Error"),
                    _("Cannot restart while a migration is running.")
                )
                return

            if self.migration_db:
                self.migration_db.close()

            import os
            os.execl(sys.executable, sys.executable, *sys.argv)

    @staticmethod
    def _load_app_icon() -> QIcon:
        """
        Load the application icon from resources/.

        Prefers the SVG, which scales cleanly to whatever size the window manager,
        task bar or alt-tab switcher asks for. Falls back to the PNG if Qt was built
        without SVG support, and finally to an empty QIcon so a missing file can
        never stop the window from opening.
        """
        resources = Path(__file__).resolve().parent.parent / 'resources'

        for filename in ('icon.svg', 'app_icon.png'):
            path = resources / filename
            if not path.exists():
                continue
            icon = QIcon(str(path))
            if not icon.isNull():
                return icon

        return QIcon()

    def _show_about(self):
        """Show about dialog"""
        about_text = f"""
<h2>{_("Directory Objects Migrator")}</h2>
<p><b>{_("Version")}:</b> {settings.APP_VERSION}</p>
<p>{_("Directory service object migrator (AD/FreeIPA) to Samba AD")}</p>
<br>
<p><b>{_("Features")}:</b></p>
<ul>
<li>{_("AD: organizational units, users, groups and contacts")}</li>
<li>{_("FreeIPA: users and groups, optional RFC2307")}</li>
<li>{_("Migration preview, identity tracking and verification")}</li>
<li>{_("Deferred references and dry-run mode")}</li>
</ul>
<br>
<p><b>GitHub:</b> <a href="https://github.com/x09/DirectoryObjectsMigrator">https://github.com/x09/DirectoryObjectsMigrator</a></p>
"""
        QMessageBox.about(self, _("About"), about_text)

    def _check_connections(self):
        """Check if connections are configured"""
        source_config = self.config_manager.get_source_dc_config()
        dest_config = self.config_manager.get_dest_dc_config()

        source_ok = bool(source_config.get('host') and source_config.get('domain'))
        dest_ok = bool(dest_config.get('host') and dest_config.get('domain'))

        if source_ok:
            self.source_status.setText(_("Source:") + f" {source_config['host']} ({source_config['domain']})")
            self.source_status.setStyleSheet("color: green;")
        else:
            self.source_status.setText(_("Source:") + " " + _("Not configured"))
            self.source_status.setStyleSheet("color: red;")

        if dest_ok:
            self.dest_status.setText(_("Destination:") + f" {dest_config['host']} ({dest_config['domain']})")
            self.dest_status.setStyleSheet("color: green;")
        else:
            self.dest_status.setText(_("Destination:") + " " + _("Not configured"))
            self.dest_status.setStyleSheet("color: red;")

        # Enable analyze button if both configured
        ipa = source_config.get('source_type', 'ad') == 'freeipa'
        self.analyze_btn.setEnabled(source_ok and (ipa or dest_ok))
        self.browse_base_dn_btn.setEnabled(source_ok and not ipa)
        self.base_dn_input.setEnabled(not ipa)
        self.base_dn_row.setVisible(not ipa)
        self.freeipa_scope_label.setVisible(ipa)
        if ipa and source_ok:
            self.source_status.setText(f"FreeIPA: {source_config['host']} ({source_config['domain']})")

    def _invalidate_analysis(self, *args):
        """A plan applies only to the scope against which it was built."""
        self.analysis_result = None
        self.migration_plan = None
        self.migrate_btn.setEnabled(False)

    def _source_browser_connection_failed(self):
        self._session_passwords['source'] = None

    def _browse_base_dn(self):
        config = self.config_manager.get_source_dc_config()
        if not all(config.get(key) for key in ('host', 'domain', 'username')):
            QMessageBox.warning(self, _("Error"), _("Please configure connections first"))
            return
        try:
            password = self._get_password('source', config['host'], config['domain'], config['username'])
        except LDAPConnectionError:
            return
        params = dict(
            host=config['host'], port=config['port'], domain=config['domain'],
            username=config['username'], password=password,
            use_tls=config.get('use_tls', settings.DEFAULT_USE_TLS),
        )
        dialog = BranchDialog(params, self)
        dialog.connection_failed.connect(self._source_browser_connection_failed)
        if dialog.exec_() == BranchDialog.Accepted:
            self.base_dn_input.setText(dialog.selected_dn)
            self.config_manager.set_last_base_dn(dialog.selected_dn)
        dialog.deleteLater()

    def _append_log(self, level: str, message: str):
        """Append log message"""
        self.log_text.append(f"[{level}] {message}")
        # Auto-scroll
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)

    def _analyze(self):
        """Analyze source domain"""
        if self.config_manager.get_source_dc_config().get('source_type', 'ad') == 'freeipa':
            self._analyze_freeipa()
            return
        base_dn = self.base_dn_input.text().strip()
        if not base_dn:
            QMessageBox.warning(self, _("Error"), _("Please specify Base DN"))
            return

        # Save last DN
        self.config_manager.set_last_base_dn(base_dn)

        self.statusBar.showMessage(_("Analyzing..."))
        self._append_log('INFO', f"Starting analysis of {base_dn}")

        try:
            # Connect to both DCs. The destination is needed too: the plan below
            # checks it so the preview can distinguish CREATE from EXISTS and
            # CONFLICT. Passwords are prompted for only once per session.
            self._ensure_source_connected()
            self._ensure_dest_connected()

            from core.analyzer import Analyzer
            self.analysis_result = None
            self.migration_plan = None
            self.migrate_btn.setEnabled(False)
            self.migration_db = self.migration_db or MigrationDB(self.config_manager.get_database_path())
            source, dest, database = self.source_conn, self.dest_conn, self.migration_db
            opts = self.config_manager.get_migration_config()
            exclusions = self.config_manager.get_custom_exclusions()

            def analyze_and_plan(worker):
                # No widgets or UI callbacks are accessed on the worker thread.
                analysis = Analyzer(source, logger=logger).analyze(
                    base_dn, include_references=True)
                worker.stage_changed.emit(_("Checking destination objects and building migration plan..."))
                planner = Migrator(
                    source_conn=source, dest_conn=dest, migration_db=database,
                    logger=logger, dry_run=True, custom_exclusions=exclusions,
                    password_mode=opts.get('password_mode', settings.DEFAULT_PASSWORD_MODE),
                    fixed_password=opts.get('fixed_password', ''),
                    password_length=opts.get('password_length', settings.DEFAULT_PASSWORD_LENGTH),
                    batch_size=opts.get('batch_size', settings.DEFAULT_BATCH_SIZE))
                return analysis, planner.build_plan(analysis)

            worker = AnalysisWorker(analyze_and_plan, self)
            worker.log_message.connect(self._append_log)
            logger = MigrationLogger(gui_callback=worker.log_message.emit)
            self.logger = logger
            dialog = AnalysisDialog(worker, self)
            worker.start()
            try:
                dialog.exec_()
                worker.wait()
                if worker.error is not None:
                    raise worker.error
                self.analysis_result, self.migration_plan = worker.result
            finally:
                worker.wait()
                logger.gui_callback = self._append_log
                dialog.deleteLater()
                worker.deleteLater()

        except Exception as e:
            self.analysis_result = None
            self.migration_plan = None
            self.migrate_btn.setEnabled(False)
            self._append_log('ERROR', f"Analysis failed: {e}")
            QMessageBox.critical(self, _("Error"), f"{_('Analysis failed')}\n{str(e)}")
            self.statusBar.showMessage(_("Analysis failed"))
            return

        summary = self.migration_plan.summary()
        self._append_log(
            'SUCCESS',
            f"Analysis complete: {self.analysis_result.total_objects} objects found "
            f"(create={summary['create']}, exists={summary['exists']}, "
            f"conflict={summary['conflict']}, deferred={summary['deferred']})"
        )

        # A successful analysis is what unlocks migration. Whether the user proceeds
        # straight from the preview or later from the main window, the plan is ready.
        self.migrate_btn.setEnabled(True)

        # Show preview. Migration is started outside the try block above so that a
        # migration setup failure is not misreported as an analysis failure.
        preview_dialog = PreviewDialog(
            self.analysis_result,
            plan=self.migration_plan,
            dry_run=self.dry_run_checkbox.isChecked(),
            parent=self
        )
        if preview_dialog.exec_() == PreviewDialog.Accepted:
            self.statusBar.showMessage(_("Ready to migrate"))
            self._start_migration()
        else:
            self.statusBar.showMessage(_("Analysis complete"))

    def _freeipa_operation(self, approved_plan=None, recreation_requests=None):
        """Capture settings on the GUI thread; connections belong to the worker."""
        from core.freeipa_migration import FreeIPAMigrator
        source_config = self.config_manager.get_source_dc_config()
        dest_config = self.config_manager.get_dest_dc_config()
        params = []
        for kind, config in [('source', source_config), ('dest', dest_config)]:
            password = self._get_password(kind, config['host'], config['domain'], config['username'])
            params.append(dict(host=config['host'], port=config['port'], domain=config['domain'],
                               username=config['username'], password=password, use_tls=config['use_tls']))
        opts = self.config_manager.get_migration_config()
        exclusions = self.config_manager.get_custom_exclusions()
        dry_run = self.dry_run_checkbox.isChecked()
        log_level = self.config_manager.get_log_level()
        database_path = self.config_manager.get_database_path()
        attribute_mappings = self.config_manager.get_freeipa_mappings()
        def operation(worker):
            source = source_connector_class('freeipa')(**params[0])
            dest = LDAPConnector(**params[1])
            database = None
            logger = MigrationLogger(gui_callback=worker.log_message.emit)
            logger.set_log_level(log_level)
            try:
                source.connect()
                dest.connect()
                database = MigrationDB(database_path)
                progress = (worker.emit_progress if approved_plan is not None else
                            lambda percent, message: worker.stage_changed.emit(message))
                migrator = FreeIPAMigrator(source, dest, database, logger,
                    source_config.get('users_target_dn') or 'CN=Users,' + dest.domain_dn,
                    source_config.get('groups_target_dn') or 'CN=Users,' + dest.domain_dn,
                    rfc2307=source_config.get('rfc2307', False), custom_exclusions=exclusions,
                    shorten_long_logins=source_config.get('shorten_long_logins', False),
                    password_mode=opts.get('password_mode', 'random'),
                    fixed_password=opts.get('fixed_password', ''),
                    password_length=opts.get('password_length', settings.DEFAULT_PASSWORD_LENGTH),
                    dry_run=dry_run, progress_callback=progress, approved_plan=approved_plan,
                    recreation_requests=recreation_requests, attribute_mappings=attribute_mappings)
                if approved_plan is None:
                    return migrator.build_plan()
                worker.migrator = migrator
                if worker.cancelled:
                    migrator.cancel()
                return migrator.migrate()
            finally:
                source.disconnect()
                dest.disconnect()
                if database:
                    database.close()
        return operation

    def _analyze_freeipa(self, recreation_requests=None):
        from gui.freeipa_discovery import FreeIPADiscoveryDialog, FreeIPAPlanDialog
        self._invalidate_analysis()
        config = self.config_manager.get_source_dc_config()
        dest = self.config_manager.get_dest_dc_config()
        planning = all(dest.get(key) for key in ('host', 'domain', 'username'))
        worker = dialog = None
        action = QDialog.Rejected
        selected_dns = []
        requested_recreations = {}
        try:
            if planning:
                operation = (self._freeipa_operation(recreation_requests=recreation_requests)
                             if recreation_requests else self._freeipa_operation())
            else:
                password = self._get_password('source', config['host'], config['domain'], config['username'])
                exclusions = self.config_manager.get_custom_exclusions()
                def operation(worker):
                    conn = source_connector_class('freeipa')(
                        host=config['host'], port=config['port'], domain=config['domain'],
                        username=config['username'], password=password, use_tls=config['use_tls'])
                    try:
                        conn.connect()
                        return conn.discover(config.get('rfc2307', False), exclusions)
                    finally:
                        conn.disconnect()
            worker = AnalysisWorker(operation, self)
            worker.log_message.connect(self._append_log)
            dialog = AnalysisDialog(worker, self)
            worker.start()
            dialog.exec_()
            worker.wait()
            if worker.error:
                raise worker.error
            if planning:
                self.migration_plan = worker.result
                self.migrate_btn.setEnabled(not self.migration_plan.blocked)
                preview = FreeIPAPlanDialog(self.migration_plan, self.dry_run_checkbox.isChecked(), self,
                                            history_path=self.config_manager.get_database_path())
                action = preview.exec_()
                selected_dns = preview.excluded_dns
                requested_recreations = preview.requested_recreations
                preview.deleteLater()
            else:
                FreeIPADiscoveryDialog(worker.result, self).exec_()
            self.statusBar.showMessage(_("Analysis complete"))
        except Exception as exc:
            self._invalidate_analysis()
            if isinstance(exc, LDAPConnectionError):
                self._session_passwords = {'source': None, 'dest': None}
            QMessageBox.critical(self, _("Analysis failed"), str(exc))
        finally:
            if worker:
                worker.wait()
                worker.deleteLater()
            if dialog:
                dialog.deleteLater()
        if action == QDialog.Accepted:
            self._start_freeipa_migration()
        elif action == FreeIPAPlanDialog.RECREATE_AND_REANALYZE:
            self._invalidate_analysis()
            QTimer.singleShot(0, lambda: self._analyze_freeipa(requested_recreations))
        elif action == FreeIPAPlanDialog.EXCLUDE_AND_REANALYZE:
            self.config_manager.set_custom_exclusions(self.config_manager.get_custom_exclusions() + selected_dns)
            self._invalidate_analysis()
            QTimer.singleShot(0, self._analyze_freeipa)
        elif action == FreeIPAPlanDialog.OPEN_SETTINGS:
            self._open_settings()
        elif action == FreeIPAPlanDialog.CHOOSE_HISTORY:
            if self._choose_history():
                QTimer.singleShot(0, self._analyze_freeipa)

    def _history_changed(self):
        if self.migration_db:
            self.migration_db.close()
            self.migration_db = None
        self.last_run_id = None
        self.report_btn.setEnabled(False)
        self._invalidate_analysis()

    def _choose_history(self):
        from gui.migration_table import choose_history_file
        path = choose_history_file(self, self.config_manager.get_database_path())
        if path:
            self.config_manager.set_database_path(path)
            self._history_changed()
            return True
        return False

    def _start_freeipa_migration(self):
        if self.migration_plan is None or self.migration_plan.blocked:
            QMessageBox.warning(self, _("Error"), _("Please run analysis first"))
            return
        try:
            operation = self._freeipa_operation(self.migration_plan)
            progress = ProgressWindow(self)
            worker = FreeIPAMigrationWorker(operation, self)
            self.migration_worker = worker
            # Reports use their own DB connection; the worker owns and closes its connection.
            if self.migration_db:
                self.migration_db.close()
            self.migration_db = MigrationDB(self.config_manager.get_database_path())
            worker.progress_update.connect(progress.update_progress)
            worker.log_message.connect(progress.append_log)
            worker.log_message.connect(self._append_log)
            worker.migration_complete.connect(lambda ok, result: self._migration_complete(progress, ok, result))
            progress.cancel_requested.connect(worker.cancel)
            worker.start()
            progress.exec_()
            worker.wait()
            worker.deleteLater()
            self.migration_worker = None
        except Exception as exc:
            QMessageBox.critical(self, _("Error"), str(exc))

    def _build_plan(self, base_dn: str):
        """
        Compute the migration plan without writing anything.

        A throwaway Migrator is used purely as the classifier, so the preview
        applies exactly the same rules as the real run. Nothing is written: only
        build_plan() is called, never migrate().
        """
        migration_opts = self.config_manager.get_migration_config()

        planner = Migrator(
            source_conn=self.source_conn,
            dest_conn=self.dest_conn,
            migration_db=self.migration_db,
            logger=self.logger or MigrationLogger(gui_callback=self._append_log),
            password_mode=migration_opts.get('password_mode', settings.DEFAULT_PASSWORD_MODE),
            fixed_password=migration_opts.get('fixed_password', ''),
            password_length=migration_opts.get('password_length', settings.DEFAULT_PASSWORD_LENGTH),
            batch_size=migration_opts.get('batch_size', settings.DEFAULT_BATCH_SIZE),
            dry_run=True,  # planning only
            custom_exclusions=self.config_manager.get_custom_exclusions(),
        )
        return planner.build_plan(self.analysis_result)

    def _get_password(self, dc_type: str, host: str, domain: str, username: str) -> str:
        """
        Return the password for a DC, prompting only if it isn't cached yet.

        Args:
            dc_type: 'source' or 'dest'
            host: DC host (shown in the prompt so the user knows which DC is meant)
            domain: DC domain
            username: Account being authenticated

        Returns:
            The password

        Raises:
            LDAPConnectionError: If the user cancels the prompt
        """
        cached = self._session_passwords.get(dc_type)
        if cached:
            return cached

        label = _("Source DC") if dc_type == 'source' else _("Destination DC")
        password, ok = QInputDialog.getText(
            self,
            f"{label} - {_('Password')}",
            f"{label}: {host} ({domain})\n{_('Username')}: {username}\n\n{_('Password')}:",
            QLineEdit.Password
        )

        if not ok:
            raise LDAPConnectionError(_("Connection cancelled"))

        if not password:
            raise LDAPConnectionError(_("Password cannot be empty"))

        self._session_passwords[dc_type] = password
        return password

    def _connect_dc(self, dc_type: str) -> LDAPConnector:
        """
        Connect to a DC, reusing the cached session password when available.

        On authentication failure the cached password is discarded so the next
        attempt prompts again instead of silently retrying a bad credential.

        Args:
            dc_type: 'source' or 'dest'

        Returns:
            A connected LDAPConnector

        Raises:
            LDAPConnectionError: If configuration is incomplete or connection fails
        """
        if dc_type == 'source':
            config = self.config_manager.get_source_dc_config()
        else:
            config = self.config_manager.get_dest_dc_config()

        if not config.get('host') or not config.get('domain'):
            raise LDAPConnectionError(_("Please configure connections first"))

        if not config.get('username'):
            raise LDAPConnectionError(_("Username is not configured"))

        password = self._get_password(
            dc_type,
            config['host'],
            config['domain'],
            config['username']
        )

        cls = source_connector_class(config.get('source_type', 'ad')) if dc_type == 'source' else LDAPConnector
        connector = cls(
            host=config['host'],
            port=config['port'],
            domain=config['domain'],
            username=config['username'],
            password=password,
            use_tls=config.get('use_tls', settings.DEFAULT_USE_TLS)
        )

        try:
            connector.connect()
        except Exception:
            # Bad password (or unreachable DC) - drop it so we re-prompt next time
            self._session_passwords[dc_type] = None
            raise

        return connector

    def _ensure_source_connected(self):
        """Connect to source DC if not already connected"""
        if not self.source_conn or not self.source_conn.is_connected():
            self.source_conn = self._connect_dc('source')
            self._append_log('SUCCESS', f"Connected to source DC: {self.source_conn.host}")

    def _ensure_dest_connected(self):
        """Connect to destination DC if not already connected"""
        if not self.dest_conn or not self.dest_conn.is_connected():
            self.dest_conn = self._connect_dc('dest')
            self._append_log('SUCCESS', f"Connected to destination DC: {self.dest_conn.host}")

    def _start_migration(self):
        """Start migration process"""
        if self.config_manager.get_source_dc_config().get('source_type', 'ad') == 'freeipa':
            self._start_freeipa_migration()
            return
        if not self.analysis_result:
            QMessageBox.warning(self, _("Error"), _("Please run analysis first"))
            return

        base_dn = self.base_dn_input.text().strip()

        try:
            # Connect to both DCs (passwords come from the session cache)
            self._ensure_source_connected()
            self._ensure_dest_connected()

            # Migration options come from the saved config, not from a fresh dialog.
            # Reopening ConnectionDialog here would present blank password fields.
            migration_opts = self.config_manager.get_migration_config()

            # Setup database and logger
            self.migration_db = MigrationDB(self.config_manager.get_database_path())

            # Create progress window
            progress_window = ProgressWindow(self)

            # Create worker thread first so its signals can carry all GUI updates.
            # Qt widgets must never be touched from the worker thread directly.
            self.migration_worker = MigrationWorker(base_dn, parent=self)

            self.migration_worker.progress_update.connect(progress_window.update_progress)
            self.migration_worker.log_message.connect(progress_window.append_log)
            self.migration_worker.log_message.connect(self._append_log)
            self.migration_worker.migration_complete.connect(
                lambda success, result: self._migration_complete(progress_window, success, result)
            )

            # Logger and progress callbacks emit signals rather than calling widgets
            self.logger = MigrationLogger(gui_callback=self.migration_worker.emit_log)
            self.logger.set_log_level(self.config_manager.get_log_level())

            # Create migrator
            self.migrator = Migrator(
                source_conn=self.source_conn,
                dest_conn=self.dest_conn,
                migration_db=self.migration_db,
                logger=self.logger,
                password_mode=migration_opts.get('password_mode', settings.DEFAULT_PASSWORD_MODE),
                fixed_password=migration_opts.get('fixed_password', ''),
                password_length=migration_opts.get('password_length', settings.DEFAULT_PASSWORD_LENGTH),
                batch_size=migration_opts.get('batch_size', settings.DEFAULT_BATCH_SIZE),
                dry_run=self.dry_run_checkbox.isChecked(),
                progress_callback=self.migration_worker.emit_progress,
                custom_exclusions=self.config_manager.get_custom_exclusions(),
            )
            self.migration_worker.migrator = self.migrator

            # Let the Cancel button reach the migrator
            progress_window.cancel_requested.connect(self.migrator.cancel)

            # Start migration
            self.migration_worker.start()
            progress_window.exec_()

        except Exception as e:
            self._append_log('ERROR', f"Migration failed: {e}")
            QMessageBox.critical(self, _("Error"), f"{_('Migration failed')}\n{str(e)}")

    def _migration_complete(self, progress_window: ProgressWindow, success: bool, result):
        """
        Handle migration completion.

        `result` is None when the worker died on an exception; otherwise it is a
        MigrationResult even for an unsuccessful run. A partial run is still worth
        reporting on, so the report button is enabled whenever a run_id exists.
        """
        if result is not None and result.run_id:
            self.last_run_id = result.run_id
            self.report_btn.setEnabled(True)

        status = result.status if result is not None else settings.RUN_STATUS_FAILED
        if result is None and progress_window.is_cancelled():
            status = settings.RUN_STATUS_CANCELLED
        message = completion_title(status)
        if result is not None:
            message += '\n' + _("Created: {created}; skipped: {skipped}; conflicts: {conflicts}; errors: {errors}").format(
                created=result.objects_created, skipped=result.objects_skipped,
                conflicts=result.objects_conflicted, errors=result.errors_count)
            if result.failure_message:
                message += '\n' + result.failure_message
            if result.verification_result:
                message += ''.join('\n' + error for error in result.verification_result.errors)
            if result.warnings:
                message += ''.join('\n' + warning for warning in result.warnings)
        progress_window.set_complete(success, message, status=status)
        self.statusBar.showMessage(completion_title(status))

        # The analysis and plan reflect pre-migration state; force a fresh pass
        # before any subsequent run so nothing stale is reused.
        self.analysis_result = None
        self.migration_plan = None
        self.migrate_btn.setEnabled(False)

    def _generate_report(self):
        """Generate migration report"""
        if not self.last_run_id:
            QMessageBox.warning(self, _("Error"), _("No migration run to report on"))
            return

        try:
            generator = ReportGenerator(self.migration_db)

            # Ask user for format
            reply = QMessageBox.question(
                self,
                _("Generate Report"),
                _("Generate HTML report?\n(No = generate text report)"),
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Yes
            )

            if reply == QMessageBox.Cancel:
                return

            if reply == QMessageBox.Yes:
                # HTML report
                report_path = generator.generate_html_report(self.last_run_id)
                self._append_log('SUCCESS', f"HTML report generated: {report_path}")

                # Ask to open
                open_reply = QMessageBox.question(
                    self,
                    _("Report Generated"),
                    f"{_('Report generated')}: {report_path}\n\n{_('Open report')}?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes
                )

                if open_reply == QMessageBox.Yes:
                    webbrowser.open(f"file://{report_path}")

            else:
                # Text report
                report_path = generator.generate_text_report(self.last_run_id)
                self._append_log('SUCCESS', f"Text report generated: {report_path}")

                QMessageBox.information(
                    self,
                    _("Report Generated"),
                    f"{_('Report generated')}: {report_path}"
                )

        except Exception as e:
            self._append_log('ERROR', f"Failed to generate report: {e}")
            QMessageBox.critical(self, _("Error"), f"{_('Failed to generate report')}\n{str(e)}")

    def _clear_log(self):
        """Clear the log viewer"""
        self.log_text.clear()
        self.statusBar.showMessage(_("Log cleared"))


if __name__ == "__main__":
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
