"""FreeIPA discovery boundaries, incomplete reads and source selection."""
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PyQt5.QtWidgets import QApplication
from core.ldap_connector import LDAPConnector, LDAPOperationError
from core.sources import source_connector_class
from core.sources.freeipa import FreeIPAConnector
from gui.connection_dialog import ConnectionDialog
from gui.main_window import MainWindow
from utils.config_manager import ConfigManager

APP = QApplication.instance() or QApplication([])
SUFFIX = 'dc=ipa,dc=test'


def connector():
    return FreeIPAConnector('ipa.test', 636, 'ipa.test', 'admin', 'unused')


def record(name, kind='user', **attrs):
    key, tree = ('uid', 'users') if kind == 'user' else ('cn', 'groups')
    return {'dn': f'{key}={name},cn={tree},cn=accounts,{SUFFIX}',
            'attributes': {key: [name], 'ipauniqueid': [str(uuid.uuid4())],
                           'objectclass': ['posixAccount' if kind == 'user' else 'ipaUserGroup'], **attrs}}


def discover(users, groups, rfc=False):
    conn = connector()
    conn.search = Mock(side_effect=[users, groups])
    result = conn.discover(rfc)
    assert all('cn=accounts' in call.args[0] for call in conn.search.call_args_list)
    return result


class DiscoveryTests(unittest.TestCase):
    def test_unblocked_users_only_and_native_trees(self):
        users = [record('new'), record('enabled', nsaccountlock=[False]),
                 record('blocked', nsaccountlock=[True]), record('unknown', nsaccountlock=['?']),
                 record('ambiguous', nsaccountlock=[False, True]), record('admin')]
        result = discover(users, [])
        self.assertEqual([o.name for o in result.eligible], ['new', 'enabled'])
        self.assertTrue(result.objects[3].error)
        self.assertTrue(result.objects[4].error)
        conn = connector()
        conn.search = Mock(return_value=[])
        conn.discover()
        self.assertEqual([c.args[0].lower() for c in conn.search.call_args_list],
                         [f'cn=users,cn=accounts,{SUFFIX}', f'cn=groups,cn=accounts,{SUFFIX}'])

    def test_personal_groups_follow_rfc_and_owner(self):
        user, blocked = record('alice'), record('locked', nsaccountlock=[True])
        groups = [record('ordinary', 'group'),
                  record('alice', 'group', mepmanagedby=[user['dn']]),
                  record('locked', 'group', mepmanagedby=[blocked['dn']]),
                  record('orphan', 'group', mepmanagedby=['uid=missing,'+SUFFIX]),
                  record('external', 'group', objectclass=['ipaExternalGroup']),
                  record('admins', 'group')]
        self.assertEqual([o.name for o in discover([user, blocked], groups).eligible], ['alice', 'ordinary'])
        self.assertEqual([o.name for o in discover([user, blocked], groups, True).eligible],
                         ['alice', 'ordinary', 'alice'])

    def test_duplicate_and_invalid_identities_are_never_eligible(self):
        a, b, c = record('a'), record('b'), record('c', ipauniqueid=['bad'])
        b['attributes']['ipauniqueid'] = a['attributes']['ipauniqueid']
        result = discover([a, b, c], [])
        self.assertEqual(result.eligible, [])
        self.assertTrue(all(o.error for o in result.objects))

    def test_operator_exclusion_also_excludes_private_group(self):
        user = record('alice')
        group = record('alice', 'group', mepmanagedby=[user['dn']])
        conn = connector()
        conn.search = Mock(side_effect=[[user], [group]])
        self.assertEqual(conn.discover(True, [user['dn']]).eligible, [])

    def test_raw_members_and_multivalued_fields_are_preserved(self):
        user = record('alice', mail=['a@ipa.test', 'b@ipa.test'], cn=['Тестовая, Мария'])
        group = record('nested', 'group', member=[user['dn'], 'cn=child,cn=groups,cn=accounts,'+SUFFIX])
        result = discover([user], [group])
        self.assertEqual(result.eligible[0].attributes['mail'], user['attributes']['mail'])
        self.assertEqual(result.eligible[1].attributes['member'], group['attributes']['member'])

    def test_configurable_optional_fields_do_not_weaken_identity_and_lock_checks(self):
        user = record('alice', sn=['Surname'])
        keys = 'ipauniqueid objectclass cn uid nsaccountlock manager gidnumber'.split()
        for readable in (True, False):
            user['attributes']['attributelevelrights'] = [', '.join(
                key + (':none' if key == 'nsaccountlock' and not readable else ':rsc') for key in keys) + ', sn:none']
            conn = connector()
            conn.search = Mock(side_effect=[[user], []])
            result = conn.discover(require_read_rights=True, profile_attributes=['sn'])
            self.assertEqual(len(result.eligible), int(readable))
            requested = conn.search.call_args_list[0].args[2]
            self.assertIn('sn', requested)
            self.assertIn('nsAccountLock', requested)
            self.assertNotIn('givenName', requested)

    def test_hidden_lock_attribute_is_not_treated_as_enabled(self):
        user = record('alice')
        keys = ('ipauniqueid objectclass cn uid nsaccountlock givenname sn displayname '
                'mail telephonenumber mobile title ou street l st postalcode '
                'employeenumber employeetype manager gidnumber').split()
        for readable in (True, False):
            user['attributes']['attributelevelrights'] = [', '.join(
                key + (':none' if key == 'nsaccountlock' and not readable else ':rsc') for key in keys)]
            conn = connector()
            conn.search = Mock(side_effect=[[user], []])
            result = conn.discover(require_read_rights=True)
            self.assertEqual(len(result.eligible), int(readable))
            self.assertEqual(result.objects[0].error, not readable)
            self.assertTrue(conn.search.call_args_list[0].kwargs['effective_rights'])

    def test_instance_id_is_server_identity_not_domain_name(self):
        conn = connector()
        conn.search = Mock(return_value=[{'attributes': {'nsuniqueid': ['29a5d38c-e8c911f1-b679d340-8fecf440']}}])
        self.assertEqual(conn.instance_identity(), '29a5d38c-e8c9-11f1-b679-d3408fecf440')
        for value in ([], ['bad'], ['0'*32]):
            conn.search.return_value = [{'attributes': {'nsuniqueid': value}}]
            with self.assertRaises(LDAPOperationError):
                conn.instance_identity()

    def test_hidden_gid_and_missing_private_owner_block_discovery(self):
        group = record('posix', 'group', objectclass=['posixGroup'],
                       attributelevelrights=['cn:r, objectClass:r, ipaUniqueID:r, gidNumber:none'])
        conn = connector()
        conn.search = Mock(side_effect=[[], [group]])
        result = conn.discover(True, require_read_rights=True)
        self.assertTrue(result.objects[0].error)
        group['attributes']['objectclass'].append('mepManagedEntry')
        self.assertTrue(discover([], [group], True).objects[0].error)

    def test_multi_page_read_and_cancellation_never_return_partial_success(self):
        from core.sources.freeipa import DiscoveryCancelled
        class Entry:
            entry_attributes = ['uid']
            def __init__(self, i):
                self.entry_dn = f'uid=user{i},' + SUFFIX
                self.i = i
            def __getitem__(self, key):
                return SimpleNamespace(values=[f'user{self.i}'])
        conn = connector()
        wire = Mock(bound=True, auto_referrals=True, response=[])
        conn.connection = wire
        def page(**kwargs):
            index = wire.search.call_count - 1
            wire.entries = [Entry(i) for i in range(index*500, min((index+1)*500, 1201))]
            cookie = str(index+1).encode() if index < 2 else b''
            wire.result = {'result': 0, 'controls': {'1.2.840.113556.1.4.319': {'value': {'cookie': cookie}}}}
        wire.search.side_effect = page
        result = conn.search(SUFFIX, '(objectClass=*)')
        self.assertEqual(len(result), 1201)
        self.assertEqual(len({row['dn'] for row in result}), 1201)
        self.assertEqual(wire.search.call_count, 3)
        wire.search.reset_mock()
        with self.assertRaises(DiscoveryCancelled):
            conn.search(SUFFIX, '(objectClass=*)', cancelled=lambda: wire.search.call_count > 0)
        self.assertEqual(wire.search.call_count, 1)
        self.assertTrue(wire.auto_referrals)

    def test_write_operations_are_rejected(self):
        conn = connector()
        for method in ('add', 'modify', 'modify_add_values', 'delete'):
            with self.assertRaises(LDAPOperationError):
                getattr(conn, method)('any', {})
        with patch('core.ldap_connector.ldap3.Server'), patch('core.ldap_connector.ldap3.Connection') as factory:
            conn.connect()
            for method in ('add', 'modify', 'modify_dn', 'delete'):
                with self.assertRaises(LDAPOperationError):
                    getattr(conn.connection, method)('any')
        self.assertEqual(conn._build_user_dn().lower(), f'uid=admin,cn=users,cn=accounts,{SUFFIX}')
        with self.assertRaises(LDAPOperationError):
            conn.get_object_by_guid('any')

    def test_paging_and_failures_do_not_return_partial_data(self):
        oid = '1.2.840.113556.1.4.319'
        def page(cookie):
            return {'result': 0, 'controls': {oid: {'value': {'cookie': cookie}}}}
        for pages, responses, succeeds in [([page(b'next'), page(b'')], [], True),
                ([page(b'next'), page(b'next')], [], False),
                ([page(b'next'), {'result': 4}], [], False),
                ([{'result': 0}], [], False),
                ([page(b'')], [{'type': 'searchResRef'}], False)]:
            with self.subTest(pages=pages, responses=responses):
                conn = connector()
                wire = Mock(bound=True, auto_referrals=True, entries=[], response=responses)
                conn.connection = wire
                iterator = iter(pages)
                def search(**kwargs):
                    wire.result = next(iterator)
                wire.search.side_effect = search
                if succeeds:
                    self.assertEqual(conn.search(SUFFIX, '(objectClass=*)'), [])
                    self.assertEqual(wire.search.call_count, 2)
                    self.assertEqual(wire.search.call_args.kwargs['paged_cookie'], b'next')
                else:
                    with self.assertRaises(LDAPOperationError):
                        conn.search(SUFFIX, '(objectClass=*)')
                self.assertTrue(wire.auto_referrals)
                self.assertTrue(wire.search.call_args.kwargs['paged_criticality'])


class SelectionTests(unittest.TestCase):
    def test_old_config_defaults_to_ad_and_provider_factory_rejects_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            config = ConfigManager(Path(temp)/'settings.ini')
            self.assertEqual(config.get_source_dc_config()['source_type'], 'ad')
            self.assertFalse(config.get_source_dc_config()['rfc2307'])
        self.assertIs(source_connector_class('ad'), LDAPConnector)
        self.assertIs(source_connector_class('freeipa'), FreeIPAConnector)
        with self.assertRaises(ValueError):
            source_connector_class('typo')

    def test_switch_save_reload_without_destination_or_connection_password(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'settings.ini'
            dialog = ConnectionDialog(ConfigManager(path))
            self.assertEqual(dialog.source_type.currentData(), 'ad')
            dialog.source_type.setCurrentIndex(dialog.source_type.findData('freeipa'))
            self.assertFalse(dialog.source_rfc2307.isHidden())
            dialog.source_rfc2307.setChecked(True)
            dialog.source_host.setText('ipa.test')
            dialog.source_domain.setText('ipa.test')
            dialog.source_username.setText('admin')
            dialog.source_password.setText('not-to-be-saved')
            with patch('gui.connection_dialog.QMessageBox.information'), patch('gui.connection_dialog.QMessageBox.warning') as warning:
                dialog._save_settings()
                warning.assert_not_called()
            saved = ConfigManager(path)
            self.assertNotIn('not-to-be-saved', path.read_text())
            second = ConnectionDialog(saved)
            self.assertEqual(second.source_type.currentData(), 'freeipa')
            self.assertTrue(second.source_rfc2307.isChecked())
            second.source_type.setCurrentIndex(0)
            self.assertTrue(second.source_rfc2307.isHidden())
            dialog.close()
            second.close()

    def test_worker_runs_off_gui_thread_and_progress_cannot_close_early(self):
        import threading
        from gui.main_window import FreeIPAMigrationWorker
        from gui.progress_window import ProgressWindow
        from core.migrator import MigrationResult
        gui_thread = threading.get_ident()
        threads = []
        results = []
        def operation(worker):
            threads.append(threading.get_ident())
            return MigrationResult(success=True, status='completed')
        worker = FreeIPAMigrationWorker(operation)
        worker.migration_complete.connect(lambda ok, result: results.append(ok))
        worker.start()
        self.assertTrue(worker.wait(3000))
        APP.processEvents()
        self.assertNotEqual(threads, [gui_thread])
        self.assertEqual(results, [True])
        dialog = ProgressWindow()
        dialog.show()
        dialog.reject()
        self.assertTrue(dialog.isVisible())
        dialog.set_complete(True, 'done')
        dialog.reject()
        self.assertFalse(dialog.isVisible())

    def test_freeipa_cannot_enter_ad_migrator(self):
        window = SimpleNamespace(config_manager=Mock(), _start_freeipa_migration=Mock())
        window.config_manager.get_source_dc_config.return_value = {'source_type': 'freeipa'}
        with patch('gui.main_window.QMessageBox.warning') as warning:
            MainWindow._start_migration(window)
            warning.assert_not_called()
            window._start_freeipa_migration.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
