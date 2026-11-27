"""Editable FreeIPA profile mappings, persisted by ConnectionDialog."""
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
                            QTableWidget,QTableWidgetItem,QComboBox,QAbstractItemView,QHeaderView)
from PyQt5.QtCore import Qt
from core.freeipa_attributes import default_mappings
from utils.i18n import _


class FreeIPAAttributeSettings(QWidget):
    def __init__(self, rows, parent=None):
        super().__init__(parent)
        layout=QVBoxLayout(self)
        note=QLabel(_("FreeIPA only. Optional profile fields are checked against both directory schemas during analysis. Invalid mappings are skipped with warnings; objects can still be created. Existing objects are not updated."))
        note.setWordWrap(True);layout.addWidget(note)
        fixed=QLabel(_("Names, GUID/SID, passwords, account state, membership and RFC2307 fields remain managed by the application. SSH: ipaSshPubKey → altSecurityIdentities stores public keys; client SSH/SSSD configuration is separate."))
        fixed.setWordWrap(True);layout.addWidget(fixed)
        self.table=QTableWidget(0,5)
        self.table.setHorizontalHeaderLabels([_("Enabled"),_("Type"),_("FreeIPA attribute"),_("Samba AD attribute"),_("Values")])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        for index,width in enumerate((100,160,190,190,190)):self.table.setColumnWidth(index,width)
        layout.addWidget(self.table)
        buttons=QHBoxLayout()
        for text,handler in [(_("Add mapping"),lambda: self.add_row()),(_("Remove selected mappings"),self.remove_selected),
                             (_("Restore default mappings"),lambda: self.load_rows(default_mappings()))]:
            button=QPushButton(text);button.clicked.connect(handler);buttons.addWidget(button)
        layout.addLayout(buttons)
        self.load_rows(rows)

    def add_row(self, data=None):
        data=data or dict(kind='user',source='',target='',mode='all',enabled=True)
        row=self.table.rowCount();self.table.insertRow(row)
        enabled=QTableWidgetItem();enabled.setFlags(Qt.ItemIsEnabled|Qt.ItemIsUserCheckable|Qt.ItemIsSelectable)
        enabled.setCheckState(Qt.Checked if data.get('enabled',True) else Qt.Unchecked)
        self.table.setItem(row,0,enabled)
        kind=QComboBox();kind.addItem(_("User"),'user');kind.addItem(_("Group"),'group')
        kind.setCurrentIndex(max(0,kind.findData(data.get('kind','user'))));self.table.setCellWidget(row,1,kind)
        for col,key in ((2,'source'),(3,'target')):self.table.setItem(row,col,QTableWidgetItem(str(data.get(key,''))))
        mode=QComboBox()
        for text,value in [(_("All values"),'all'),(_("Primary value"),'primary'),(_("Remaining values"),'remaining')]:mode.addItem(text,value)
        mode.setCurrentIndex(max(0,mode.findData(data.get('mode','all'))));self.table.setCellWidget(row,4,mode)

    def load_rows(self, rows):
        self.table.setRowCount(0)
        for row in rows:self.add_row(row)

    def remove_selected(self):
        for index in sorted({i.row() for i in self.table.selectionModel().selectedRows()},reverse=True):self.table.removeRow(index)

    def rows(self):
        return [dict(enabled=self.table.item(i,0).checkState()==Qt.Checked,
                     kind=self.table.cellWidget(i,1).currentData(),
                     source=self.table.item(i,2).text().strip(),target=self.table.item(i,3).text().strip(),
                     mode=self.table.cellWidget(i,4).currentData()) for i in range(self.table.rowCount())]
