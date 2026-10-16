"""Branch browser regression tests: LDAP paging, lazy loading and thread lifetime."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import sys
import time
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ldap3
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QDialogButtonBox, QAbstractItemView
from core.ldap_connector import LDAPConnector, LDAPOperationError, LDAPConnectionError
from gui.branch_dialog import BranchDialog
from gui.main_window import MainWindow

app = QApplication.instance() or QApplication([])
ROOT = 'DC=source,DC=test'
SALES = r'OU=Продажи\, Восток,' + ROOT
PARAMS = dict(host='dc', port=389, domain='source.test', username='admin', password='secret', use_tls=False)


def until(condition):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            return
        time.sleep(.005)
    raise AssertionError('Timed out waiting for browser')


class Directory:
    domain_dn = ROOT

    def __init__(self, **kwargs):
        self.calls = []
        self.thread_ids = []
        self.fail_once = set()
        self.gate = None
        self.disconnected = False

    def connect(self, **kwargs):
        self.thread_ids.append(threading.get_ident())

    def get_object_by_dn(self, dn, attrs):
        return {'dn': dn}

    def list_child_containers(self, dn, cancelled):
        self.calls.append(dn)
        self.thread_ids.append(threading.get_ident())
        if self.gate:
            self.gate.wait(3)
        if dn in self.fail_once:
            self.fail_once.remove(dn)
            raise LDAPOperationError('Access denied')
        if dn == ROOT:
            return [dict(dn=SALES, name='Продажи, Восток', kind='ou'),
                    dict(dn='CN=Users,' + ROOT, name='Users', kind='container')]
        return []

    def disconnect(self):
        self.thread_ids.append(threading.get_ident())
        self.disconnected = True


class LDAPChildrenTests(unittest.TestCase):
    def connector(self, rows, result=None):
        connector = LDAPConnector(**PARAMS)
        connector._ensure_connected = Mock()
        connector.connection = Mock()
        connector.connection.auto_referrals = True
        connector.connection.result = result or {'result': 0}
        connector.connection.extend.standard.paged_search.return_value = iter(rows)
        return connector

    def test_paging_scope_unicode_and_sorting(self):
        rows = [dict(type='searchResEntry', dn=f'OU={i},{ROOT}',
                     attributes={'name': f'{i:04}', 'objectClass': ['organizationalUnit']})
                for i in range(1200)]
        rows.append(dict(type='searchResEntry', dn=SALES,
                         attributes={'name': 'Продажи, Восток', 'objectClass': ['organizationalUnit']}))
        connector = self.connector(rows)
        children = connector.list_child_containers(ROOT)
        self.assertEqual(len(children), 1201)
        self.assertEqual(children[-1]['dn'], SALES)
        kwargs = connector.connection.extend.standard.paged_search.call_args.kwargs
        self.assertEqual(kwargs['search_scope'], ldap3.LEVEL)
        self.assertEqual(kwargs['paged_size'], 500)
        self.assertTrue(kwargs['generator'])
        self.assertEqual(kwargs['attributes'], ['name', 'objectClass'])
        connector.connection.add.assert_not_called()
        connector.connection.modify.assert_not_called()

    def test_empty_and_failed_page(self):
        self.assertEqual(self.connector([]).list_child_containers(ROOT), [])
        with self.assertRaises(LDAPOperationError):
            self.connector([], {'result': 4, 'description': 'sizeLimitExceeded'}).list_child_containers(ROOT)
        self.assertEqual(self.connector([{'type': 'searchResRef'}]).list_child_containers(ROOT), [])

    def test_ad_continuation_references_do_not_discard_domain_children(self):
        rows = [
            {'type': 'searchResRef', 'uri': ['ldap://dc/DC=DomainDnsZones,' + ROOT]},
            {'type': 'searchResEntry', 'dn': SALES,
             'attributes': {'name': 'Продажи, Восток', 'objectClass': ['organizationalUnit']}},
            {'type': 'searchResRef', 'uri': ['ldap://dc/DC=ForestDnsZones,' + ROOT]},
            {'type': 'searchResEntry', 'dn': 'CN=Users,' + ROOT,
             'attributes': {'name': 'Users', 'objectClass': ['container']}},
        ]
        connector = self.connector([])
        def responses(**kwargs):
            for row in rows:
                self.assertFalse(connector.connection.auto_referrals)
                yield row
        connector.connection.extend.standard.paged_search.side_effect = responses
        children = connector.list_child_containers(ROOT)
        self.assertEqual({row['dn'] for row in children}, {SALES, 'CN=Users,' + ROOT})
        self.assertTrue(connector.connection.auto_referrals)

    def test_referrals_do_not_hide_failed_page_and_settings_are_restored(self):
        connector = self.connector([{'type': 'searchResRef'}], {'result': 4})
        with self.assertRaises(LDAPOperationError):
            connector.list_child_containers(ROOT)
        self.assertTrue(connector.connection.auto_referrals)
        connector.connection.auto_referrals = False
        connector.connection.result = {'result': 0}
        connector.connection.extend.standard.paged_search.side_effect = LDAPOperationError('failure')
        with self.assertRaises(LDAPOperationError):
            connector.list_child_containers(ROOT)
        self.assertFalse(connector.connection.auto_referrals)


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.directory = Directory()
        self.dialog = BranchDialog(PARAMS, connector_factory=lambda **kwargs: self.directory)
        self.assertFalse(self.dialog.loading_indicator.isHidden())
        self.dialog.show()
        until(lambda: self.dialog._states.get(ROOT) == 'loaded')
        self.assertTrue(self.dialog.loading_indicator.isHidden())

    def tearDown(self):
        if self.directory.gate:
            self.directory.gate.set()
        if self.dialog._closing_result is None:
            self.dialog.reject()
        until(lambda: not self.dialog.loader.isRunning())
        app.processEvents()
        self.dialog.deleteLater()
        app.processEvents()

    def test_lazy_cache_and_single_selection(self):
        self.assertEqual(self.directory.calls, [ROOT])
        self.assertEqual(self.dialog.tree.selectionMode(), QAbstractItemView.SingleSelection)
        self.assertFalse(self.dialog.select_btn.isEnabled())
        item = self.dialog._items[SALES]
        self.dialog.tree.setCurrentItem(item)
        self.assertIn(SALES, self.dialog.dn_label.text())
        item.setExpanded(True)
        self.assertTrue(self.dialog.loading_indicator.isVisible())
        self.assertIn('Loading branch', item.text(0))
        until(lambda: self.dialog._states[SALES] == 'loaded')
        self.assertTrue(self.dialog.loading_indicator.isHidden())
        self.assertEqual(item.text(0), 'Продажи, Восток')
        self.assertEqual(item.childCount(), 0)
        item.setExpanded(False)
        item.setExpanded(True)
        self.assertEqual(self.directory.calls.count(SALES), 1)
        self.dialog.accept()
        until(lambda: not self.dialog.isVisible())
        self.assertEqual(self.dialog.selected_dn, SALES)
        self.assertTrue(self.directory.disconnected)
        self.assertTrue(all(t != threading.get_ident() for t in self.directory.thread_ids))
        self.assertEqual(self.dialog.loader.params, {})

    def test_error_is_retryable_and_refresh_clears_cache(self):
        self.directory.fail_once.add(SALES)
        item = self.dialog._items[SALES]
        item.setExpanded(True)
        until(lambda: self.dialog._states[SALES] == 'error')
        self.assertIn('Access denied', self.dialog.status.text())
        self.assertTrue(self.dialog.loading_indicator.isHidden())
        self.assertEqual(item.text(0), 'Продажи, Восток')
        self.assertFalse(item.isExpanded())
        item.setExpanded(True)
        until(lambda: self.dialog._states[SALES] == 'loaded')
        self.assertEqual(self.directory.calls.count(SALES), 2)
        self.dialog._refresh()
        until(lambda: self.directory.calls.count(ROOT) == 2 and self.dialog._states[ROOT] == 'loaded')
        self.assertEqual(self.dialog._states[SALES], 'new')

    def test_cancel_during_query_keeps_thread_alive_until_safe_close(self):
        self.directory.gate = threading.Event()
        self.dialog._items[SALES].setExpanded(True)
        until(lambda: SALES in self.directory.calls)
        self.dialog.close()
        self.assertTrue(self.dialog.loader.isRunning())
        self.assertTrue(self.dialog.isVisible())
        self.assertFalse(self.dialog.tree.isEnabled())
        self.assertTrue(self.dialog.loading_indicator.isVisible())
        self.directory.gate.set()
        until(lambda: not self.dialog.isVisible())
        self.assertIsNone(self.dialog.selected_dn)
        self.assertTrue(self.directory.disconnected)

    def test_root_can_be_selected(self):
        self.dialog.tree.setCurrentItem(self.dialog._items[ROOT])
        self.dialog.accept()
        until(lambda: not self.dialog.isVisible())
        self.assertEqual(self.dialog.selected_dn, ROOT)

    def test_main_window_scope_change_invalidates_plan(self):
        with patch('gui.main_window.ConfigManager') as config:
            config.return_value.get_last_base_dn.return_value = ''
            config.return_value.get_source_dc_config.return_value = {'host': 'dc', 'domain': 'source.test'}
            config.return_value.get_dest_dc_config.return_value = {}
            window = MainWindow()
        self.assertTrue(window.browse_base_dn_btn.isEnabled())
        self.assertFalse(window.analyze_btn.isEnabled())
        window.analysis_result = object()
        window.migration_plan = object()
        window.migrate_btn.setEnabled(True)
        window.base_dn_input.setText(SALES)
        self.assertIsNone(window.analysis_result)
        self.assertIsNone(window.migration_plan)
        self.assertFalse(window.migrate_btn.isEnabled())
        window.close()

    def test_browse_accept_and_cancel_integration(self):
        with patch('gui.main_window.ConfigManager') as config:
            config.return_value.get_last_base_dn.return_value = ''
            config.return_value.get_source_dc_config.return_value = PARAMS
            config.return_value.get_dest_dc_config.return_value = {}
            window = MainWindow()
        with patch.object(window, '_get_password', return_value='secret'), \
                patch('gui.main_window.BranchDialog') as browser:
            browser.Accepted = 1
            browser.return_value.exec_.return_value = 1
            browser.return_value.selected_dn = SALES
            window._browse_base_dn()
            self.assertEqual(window.base_dn_input.text(), SALES)
            window.config_manager.set_last_base_dn.assert_called_with(SALES)
            self.assertEqual(browser.call_args.args[0]['host'], PARAMS['host'])
            window.analysis_result = 'unchanged'
            browser.return_value.exec_.return_value = 0
            window._browse_base_dn()
            self.assertEqual(window.base_dn_input.text(), SALES)
            self.assertEqual(window.analysis_result, 'unchanged')
        window.close()

    def test_connection_failure_leaves_root_unselectable(self):
        self.dialog.reject()
        until(lambda: not self.dialog.loader.isRunning())
        directory = Directory()
        directory.connect = Mock(side_effect=LDAPConnectionError('Bad credentials'))
        self.dialog = BranchDialog(PARAMS, connector_factory=lambda **kwargs: directory)
        failures = []
        self.dialog.connection_failed.connect(lambda: failures.append(True))
        self.dialog.show()
        until(lambda: self.dialog._states.get(ROOT) == 'error')
        self.assertEqual(failures, [True])
        self.assertFalse(self.dialog._items[ROOT].flags() & Qt.ItemIsSelectable)
        self.assertIn('Bad credentials', self.dialog.status.text())


if __name__ == '__main__':
    unittest.main()
