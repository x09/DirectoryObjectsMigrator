"""
Connection Dialog
Dialog for configuring Source and Destination DC connections
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QLineEdit, QSpinBox, QCheckBox, QPushButton, QLabel,
    QRadioButton, QButtonGroup, QMessageBox, QTabWidget, QWidget, QTextEdit
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon

from core.ldap_connector import LDAPConnector, LDAPConnectionError
from utils.config_manager import ConfigManager
from utils.i18n import _
from config import settings


class ConnectionDialog(QDialog):
    """Dialog for configuring LDAP connections"""

    # Signal emitted when connections are saved
    connections_saved = pyqtSignal()

    # Emitted after the migration history is cleared, so the main window can drop
    # any analysis or plan it is holding: both were computed against the old state.
    database_reset = pyqtSignal()

    def __init__(self, config_manager: ConfigManager, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setWindowTitle(_("Connection Settings"))
        self.setMinimumWidth(600)
        self.setModal(True)

        self._init_ui()
        self._load_settings()

    def _init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)

        # Tab widget for Source/Destination
        self.tabs = QTabWidget()

        # Source DC tab
        self.source_tab = self._create_dc_tab('source')
        self.tabs.addTab(self.source_tab, _("Source DC"))

        # Destination DC tab
        self.dest_tab = self._create_dc_tab('dest')
        self.tabs.addTab(self.dest_tab, _("Destination DC"))

        # Migration options tab
        self.options_tab = self._create_options_tab()
        self.tabs.addTab(self.options_tab, _("Migration Options"))

        # Custom exclusions tab
        self.exclusions_tab = self._create_exclusions_tab()
        self.tabs.addTab(self.exclusions_tab, _("Custom Exclusions"))

        layout.addWidget(self.tabs)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.test_btn = QPushButton(_("Test Connection"))
        self.test_btn.clicked.connect(self._test_connection)
        button_layout.addWidget(self.test_btn)

        self.save_btn = QPushButton(_("Save"))
        self.save_btn.clicked.connect(self._save_settings)
        self.save_btn.setDefault(True)
        button_layout.addWidget(self.save_btn)

        self.cancel_btn = QPushButton(_("Cancel"))
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

    def _create_dc_tab(self, dc_type: str) -> QWidget:
        """
        Create DC configuration tab

        Args:
            dc_type: 'source' or 'dest'

        Returns:
            QWidget with DC settings
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Connection group
        conn_group = QGroupBox(_("Connection"))
        conn_layout = QFormLayout()

        # Host
        host_input = QLineEdit()
        host_input.setPlaceholderText("192.168.1.1")
        setattr(self, f'{dc_type}_host', host_input)
        conn_layout.addRow(_("Host / IP Address:"), host_input)

        # Port
        port_input = QSpinBox()
        port_input.setRange(1, 65535)
        port_input.setValue(settings.DEFAULT_LDAP_PORT)
        setattr(self, f'{dc_type}_port', port_input)
        conn_layout.addRow(_("Port:"), port_input)

        # Domain
        domain_input = QLineEdit()
        domain_input.setPlaceholderText("domain.alt")
        setattr(self, f'{dc_type}_domain', domain_input)
        conn_layout.addRow(_("Domain:"), domain_input)

        # Username
        username_input = QLineEdit()
        username_input.setPlaceholderText("administrator")
        setattr(self, f'{dc_type}_username', username_input)
        conn_layout.addRow(_("Username:"), username_input)

        # Password
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        setattr(self, f'{dc_type}_password', password_input)
        conn_layout.addRow(_("Password:"), password_input)

        # Use TLS
        tls_checkbox = QCheckBox(_("Use TLS"))
        tls_checkbox.setChecked(settings.DEFAULT_USE_TLS)
        setattr(self, f'{dc_type}_tls', tls_checkbox)
        conn_layout.addRow("", tls_checkbox)

        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)

        layout.addStretch()

        return widget

    def _create_options_tab(self) -> QWidget:
        """Create migration options tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Batch size
        batch_group = QGroupBox(_("Performance"))
        batch_layout = QFormLayout()

        self.batch_size = QSpinBox()
        self.batch_size.setRange(1, 1000)
        self.batch_size.setValue(settings.DEFAULT_BATCH_SIZE)
        batch_layout.addRow(_("Batch Size:"), self.batch_size)

        batch_group.setLayout(batch_layout)
        layout.addWidget(batch_group)

        # Password policy
        password_group = QGroupBox(_("Password Policy"))
        password_layout = QVBoxLayout()

        self.password_mode_group = QButtonGroup(self)

        self.random_password_radio = QRadioButton(_("Random Password"))
        self.password_mode_group.addButton(self.random_password_radio, 0)
        password_layout.addWidget(self.random_password_radio)

        # Password length
        length_layout = QHBoxLayout()
        length_layout.addSpacing(20)
        length_layout.addWidget(QLabel(_("Length:")))
        self.password_length = QSpinBox()
        self.password_length.setRange(8, 64)
        self.password_length.setValue(settings.DEFAULT_PASSWORD_LENGTH)
        length_layout.addWidget(self.password_length)
        length_layout.addStretch()
        password_layout.addLayout(length_layout)

        self.fixed_password_radio = QRadioButton(_("Fixed Password"))
        self.password_mode_group.addButton(self.fixed_password_radio, 1)
        password_layout.addWidget(self.fixed_password_radio)

        # Fixed password input
        fixed_layout = QHBoxLayout()
        fixed_layout.addSpacing(20)
        self.fixed_password = QLineEdit()
        self.fixed_password.setEchoMode(QLineEdit.Password)
        self.fixed_password.setPlaceholderText(_("Enter fixed password"))
        fixed_layout.addWidget(self.fixed_password)
        password_layout.addLayout(fixed_layout)

        self.random_password_radio.setChecked(True)
        self.random_password_radio.toggled.connect(self._password_mode_changed)

        password_group.setLayout(password_layout)
        layout.addWidget(password_group)

        # Migration database maintenance
        db_group = QGroupBox(_("Migration Database"))
        db_layout = QVBoxLayout()

        self.db_status_label = QLabel()
        self.db_status_label.setWordWrap(True)
        db_layout.addWidget(self.db_status_label)

        reset_row = QHBoxLayout()
        self.reset_db_btn = QPushButton(_("Reset Database"))
        self.reset_db_btn.clicked.connect(self._reset_database)
        reset_row.addWidget(self.reset_db_btn)

        self.compact_db_btn = QPushButton(_("Compact"))
        self.compact_db_btn.clicked.connect(self._compact_database)
        reset_row.addWidget(self.compact_db_btn)

        reset_row.addStretch()
        db_layout.addLayout(reset_row)

        hint = QLabel(
            "<i>" +
            _("Reset: clears the migration history so the next run starts from "
              "scratch. Neither domain controller is touched: objects already "
              "created in the destination remain, but will be reported as CONFLICT "
              "instead of EXISTS. A backup copy is made first.") +
            "<br><br>" +
            _("Compact: reclaims unused space and defragments the database file. "
              "Safe to run anytime; does not delete migration history.") +
            "</i>"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #555;")
        db_layout.addWidget(hint)

        db_group.setLayout(db_layout)
        layout.addWidget(db_group)

        layout.addStretch()

        self._refresh_db_status()

        return widget

    def _create_exclusions_tab(self) -> QWidget:
        """Create custom exclusions configuration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Instructions
        instructions = QLabel(
            _("Enter Distinguished Names (DNs) to exclude from migration, one per line.\n"
              "Lines starting with # or ; are treated as comments.\n"
              "Example: CN=TestUser,OU=Sales,DC=example,DC=com")
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        # Multi-line text editor for DNs
        self.exclusions_text = QTextEdit()
        self.exclusions_text.setPlaceholderText(
            _("CN=User1,OU=Test,DC=example,DC=com\n"
              "# This is a comment\n"
              "CN=User2,OU=Test,DC=example,DC=com")
        )

        # Load existing exclusions
        exclusions = self.config_manager.get_custom_exclusions()
        if exclusions:
            self.exclusions_text.setPlainText('\n'.join(exclusions))

        layout.addWidget(self.exclusions_text)

        return tab

    def _refresh_db_status(self):
        """Show what the migration database currently holds."""
        try:
            from database.migration_db import MigrationDB

            with MigrationDB() as db:
                counts = db.counts()
                runs = counts.get('migration_runs', 0)
                objects = counts.get('migration_map', 0)
                deferred = len(db.get_unresolved_references())
                empty = db.is_empty()
        except Exception as e:
            self.db_status_label.setText(
                f"<b>{_('Error')}:</b> {_('Could not read the migration database')}: {e}")
            self.reset_db_btn.setEnabled(False)
            return

        self.db_status_label.setText(
            f"<b>{_('File')}:</b> {settings.DB_FILE}<br>"
            f"<b>{_('Migration runs')}:</b> {runs} &nbsp;|&nbsp; "
            f"<b>{_('Tracked objects')}:</b> {objects} &nbsp;|&nbsp; "
            f"<b>{_('Pending references')}:</b> {deferred}"
        )

        # Nothing to clear in a fresh database
        self.reset_db_btn.setEnabled(not empty)
        if empty:
            self.db_status_label.setText(
                self.db_status_label.text() +
                f"<br><i>{_('Database is already empty.')}</i>")

    def _reset_database(self):
        """Clear the migration history after an explicit confirmation."""
        from database.migration_db import MigrationDB

        try:
            with MigrationDB() as db:
                counts = db.counts()
                total = sum(counts.values())

                if total == 0:
                    QMessageBox.information(
                        self, _("Info"), _("Database is already empty."))
                    self._refresh_db_status()
                    return

                detail = "\n".join(
                    f"  {table}: {count}"
                    for table, count in counts.items() if count
                )

                reply = QMessageBox.warning(
                    self,
                    _("Reset Database"),
                    _("This will delete the entire migration history:") +
                    f"\n\n{detail}\n\n" +
                    _("Objects already created in the destination domain will no "
                      "longer be recognised as migrated, and the next run will "
                      "report them as CONFLICT. Nothing is deleted from either "
                      "domain controller.") + "\n\n" +
                    _("A backup copy will be created first. Continue?"),
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )

                if reply != QMessageBox.Yes:
                    return

                info = db.reset(make_backup=True)

        except Exception as e:
            QMessageBox.critical(
                self, _("Error"),
                f"{_('Failed to reset the database')}\n{e}")
            return

        backup = info.get('backup_path')
        message = _("Migration history cleared") + f" ({info['total']} " + _("rows") + ")."
        if backup:
            message += "\n\n" + _("Backup saved to:") + f"\n{backup}"

        QMessageBox.information(self, _("Success"), message)
        self.database_reset.emit()
        self._refresh_db_status()

    def _compact_database(self):
        """Reclaim unused space without deleting migration history."""
        from database.migration_db import MigrationDB

        try:
            with MigrationDB() as db:
                info = db.vacuum()
        except Exception as e:
            QMessageBox.critical(
                self, _("Error"),
                f"{_('Failed to compact the database')}\n{e}")
            return

        def fmt(b):
            if b < 1024:
                return f"{b} B"
            elif b < 1024**2:
                return f"{b/1024:.1f} KB"
            else:
                return f"{b/(1024**2):.1f} MB"

        before = fmt(info['size_before'])
        after = fmt(info['size_after'])
        freed = fmt(info['freed'])

        if info['freed'] > 0:
            message = (
                _("Database compacted successfully.") + "\n\n" +
                _("Size before: {before}\nSize after: {after}\nFreed: {freed}").format(
                    before=before, after=after, freed=freed))
        else:
            message = _("Database is already compact ({size}).").format(size=after)

        QMessageBox.information(self, _("Success"), message)
        self._refresh_db_status()

    def _password_mode_changed(self, checked):
        """Handle password mode change"""
        is_random = self.random_password_radio.isChecked()
        self.password_length.setEnabled(is_random)
        self.fixed_password.setEnabled(not is_random)

    def _load_settings(self):
        """Load settings from config"""
        # Source DC
        source_config = self.config_manager.get_source_dc_config()
        self.source_host.setText(source_config.get('host', ''))
        self.source_port.setValue(source_config.get('port', settings.DEFAULT_LDAP_PORT))
        self.source_domain.setText(source_config.get('domain', ''))
        self.source_username.setText(source_config.get('username', ''))
        self.source_tls.setChecked(source_config.get('use_tls', settings.DEFAULT_USE_TLS))

        # Destination DC
        dest_config = self.config_manager.get_dest_dc_config()
        self.dest_host.setText(dest_config.get('host', ''))
        self.dest_port.setValue(dest_config.get('port', settings.DEFAULT_LDAP_PORT))
        self.dest_domain.setText(dest_config.get('domain', ''))
        self.dest_username.setText(dest_config.get('username', ''))
        self.dest_tls.setChecked(dest_config.get('use_tls', settings.DEFAULT_USE_TLS))

        # Migration options
        migration_config = self.config_manager.get_migration_config()
        self.batch_size.setValue(migration_config.get('batch_size', settings.DEFAULT_BATCH_SIZE))
        self.password_length.setValue(migration_config.get('password_length', settings.DEFAULT_PASSWORD_LENGTH))

        password_mode = migration_config.get('password_mode', settings.DEFAULT_PASSWORD_MODE)
        if password_mode == settings.PASSWORD_MODE_FIXED:
            self.fixed_password_radio.setChecked(True)
            self.fixed_password.setText(migration_config.get('fixed_password', ''))
        else:
            self.random_password_radio.setChecked(True)

        self._password_mode_changed(False)  # Call with dummy argument

    def _save_settings(self):
        """Save settings to config"""
        # Validate
        if not self.source_host.text() or not self.source_domain.text():
            QMessageBox.warning(self, _("Error"), _("Please fill in all Source DC fields"))
            return

        if not self.dest_host.text() or not self.dest_domain.text():
            QMessageBox.warning(self, _("Error"), _("Please fill in all Destination DC fields"))
            return

        if self.fixed_password_radio.isChecked() and not self.fixed_password.text():
            QMessageBox.warning(self, _("Error"), _("Please enter fixed password or choose random mode"))
            return

        # Save source DC
        self.config_manager.set_source_dc_config({
            'host': self.source_host.text(),
            'port': self.source_port.value(),
            'domain': self.source_domain.text(),
            'username': self.source_username.text(),
            'use_tls': self.source_tls.isChecked(),
        })

        # Save destination DC
        self.config_manager.set_dest_dc_config({
            'host': self.dest_host.text(),
            'port': self.dest_port.value(),
            'domain': self.dest_domain.text(),
            'username': self.dest_username.text(),
            'use_tls': self.dest_tls.isChecked(),
        })

        # Save migration options
        password_mode = settings.PASSWORD_MODE_FIXED if self.fixed_password_radio.isChecked() else settings.PASSWORD_MODE_RANDOM
        self.config_manager.set_migration_config({
            'batch_size': self.batch_size.value(),
            'password_mode': password_mode,
            'password_length': self.password_length.value(),
            'fixed_password': self.fixed_password.text() if password_mode == settings.PASSWORD_MODE_FIXED else '',
        })

        # Save custom exclusions
        self.config_manager.set_custom_exclusions(self.exclusions_text.toPlainText())

        QMessageBox.information(self, _("Success"), _("Settings saved successfully"))
        self.connections_saved.emit()
        self.accept()

    def _test_connection(self):
        """Test current tab connection"""
        current_tab = self.tabs.currentIndex()

        if current_tab == 0:  # Source
            self._test_dc_connection('source')
        elif current_tab == 1:  # Destination
            self._test_dc_connection('dest')
        else:
            QMessageBox.information(self, _("Info"), _("Switch to Source or Destination tab to test"))

    def _test_dc_connection(self, dc_type: str):
        """Test DC connection"""
        host = getattr(self, f'{dc_type}_host').text()
        port = getattr(self, f'{dc_type}_port').value()
        domain = getattr(self, f'{dc_type}_domain').text()
        username = getattr(self, f'{dc_type}_username').text()
        password = getattr(self, f'{dc_type}_password').text()
        use_tls = getattr(self, f'{dc_type}_tls').isChecked()

        if not host or not domain or not username or not password:
            QMessageBox.warning(self, _("Error"), _("Please fill in all connection fields"))
            return

        try:
            connector = LDAPConnector(
                host=host,
                port=port,
                domain=domain,
                username=username,
                password=password,
                use_tls=use_tls
            )

            success, message = connector.test_connection()

            if success:
                QMessageBox.information(self, _("Success"), _("Connection successful") + f"\n{message}")
            else:
                QMessageBox.critical(self, _("Error"), _("Connection failed") + f"\n{message}")

        except Exception as e:
            QMessageBox.critical(self, _("Error"), f"{_('Connection failed')}\n{str(e)}")

    def get_source_connection_params(self) -> dict:
        """Get source connection parameters including password"""
        return {
            'host': self.source_host.text(),
            'port': self.source_port.value(),
            'domain': self.source_domain.text(),
            'username': self.source_username.text(),
            'password': self.source_password.text(),
            'use_tls': self.source_tls.isChecked(),
        }

    def get_dest_connection_params(self) -> dict:
        """Get destination connection parameters including password"""
        return {
            'host': self.dest_host.text(),
            'port': self.dest_port.value(),
            'domain': self.dest_domain.text(),
            'username': self.dest_username.text(),
            'password': self.dest_password.text(),
            'use_tls': self.dest_tls.isChecked(),
        }

    def get_migration_options(self) -> dict:
        """Get migration options"""
        password_mode = settings.PASSWORD_MODE_FIXED if self.fixed_password_radio.isChecked() else settings.PASSWORD_MODE_RANDOM

        return {
            'batch_size': self.batch_size.value(),
            'password_mode': password_mode,
            'password_length': self.password_length.value(),
            'fixed_password': self.fixed_password.text() if password_mode == settings.PASSWORD_MODE_FIXED else '',
        }
