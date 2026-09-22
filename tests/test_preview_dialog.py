"""
PreviewDialog rendering.

The dialog was rewritten to consume a MigrationPlan instead of raw source counts.
These tests build a real plan from a real migration run and assert the widget
actually shows the CREATE / EXISTS / CONFLICT / DEFERRED breakdown, rather than
just constructing without raising.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

if not os.environ.get('DISPLAY') and not os.environ.get('QT_QPA_PLATFORM'):
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'

from PyQt5.QtWidgets import QApplication

app = QApplication.instance() or QApplication([])

from tests.fake_ldap import FakeLDAPConnector
from core.analyzer import Analyzer
from core.migrator import Migrator
from database.migration_db import MigrationDB
from gui.preview_dialog import PreviewDialog
from utils.logger import MigrationLogger

SRC = 'DC=source,DC=alt'
DST = 'DC=dest,DC=alt'
L2 = f'OU=Level2,OU=Level1,{SRC}'
L5 = f'OU=Level5,{SRC}'

FAILURES = []


def check(label, actual, expected):
    ok = actual == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
          f"{'' if ok else f' (expected {expected!r})'}")
    if not ok:
        FAILURES.append(label)


def table_column(table, col):
    """Every value in one column of a QTableWidget."""
    values = []
    for row in range(table.rowCount()):
        item = table.item(row, col)
        values.append(item.text() if item else None)
    return values


def main():
    tmp = Path(tempfile.mkdtemp())
    db = MigrationDB(tmp / 'm.db')
    logger = MigrationLogger(log_file=tmp / 't.log')
    logger.set_log_level('ERROR')

    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(L2, ['organizationalUnit'], ou='Level2')
    src.seed(L5, ['organizationalUnit'], ou='Level5')
    src.seed(f'CN=user1,{L2}', ['user'], cn='user1', sAMAccountName='user1')
    src.seed(f'CN=user2,{L2}', ['user'], cn='user2', sAMAccountName='user2')
    src.seed(f'CN=user5,{L5}', ['user'], cn='user5', sAMAccountName='user5')
    src.seed(f'CN=group1,{L2}', ['group'], cn='group1', sAMAccountName='group1',
             groupType=-2147483646,
             member=[f'CN=user1,{L2}', f'CN=user2,{L2}', f'CN=user5,{L5}'])

    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')

    # An untracked object in the destination, to produce a CONFLICT row
    src.seed(f'CN=user9,{L2}', ['user'], cn='user9', sAMAccountName='user9')
    dst.seed(f'CN=user9,OU=Level2,OU=Level1,{DST}', ['user'],
             cn='user9', sAMAccountName='user9')

    def build_plan():
        analysis = Analyzer(src).analyze(L2, include_references=True)
        planner = Migrator(source_conn=src, dest_conn=dst, migration_db=db,
                           logger=logger, dry_run=True)
        return analysis, planner.build_plan(analysis)

    analysis, plan = build_plan()

    print("\n=== Dialog renders a fresh plan ===")
    dialog = PreviewDialog(analysis, plan=plan, dry_run=False)
    check("dialog constructed", isinstance(dialog, PreviewDialog), True)

    actions = table_column(dialog.plan_table, 0)
    check("plan table row count matches the plan",
          dialog.plan_table.rowCount(),
          len(plan.create) + len(plan.exists) + len(plan.conflict) + len(plan.errors))
    check("CREATE rows shown", actions.count('CREATE'), len(plan.create))
    check("CONFLICT rows shown", actions.count('CONFLICT'), len(plan.conflict))

    dns = table_column(dialog.plan_table, 3)
    check("destination DNs point at the dest domain",
          all(d and DST in d for d in dns), True)

    print("\n=== Deferred tab ===")
    check("deferred table row count", dialog.deferred_table.rowCount(), len(plan.deferred))
    check("deferred references present", len(plan.deferred) > 0, True)

    print("\n=== Summary text reflects the plan ===")
    summary = dialog.summary_label.text()
    s = plan.summary()
    check("summary mentions the create count", f"{s['create']}" in summary, True)
    check("summary names the source base DN", plan.base_dn in summary, True)
    check("summary names the destination base DN", plan.dest_base_dn in summary, True)

    print("\n=== Notes warn about conflicts ===")
    notes = dialog.notes_text.toPlainText()
    check("conflict warning present", 'CONFLICT' in notes.upper(), True)
    check("disabled-account note present when creating",
          'disabled' in notes.lower(), True)

    print("\n=== Dry-run wording ===")
    dry_dialog = PreviewDialog(analysis, plan=plan, dry_run=True)
    check("button offers a dry run",
          'dry' in dry_dialog.proceed_btn.text().lower(), True)
    check("notes state nothing will be written",
          'not be modified' in dry_dialog.notes_text.toPlainText().lower(), True)

    print("\n=== Repeat run shows EXISTS instead of CREATE ===")
    Migrator(source_conn=src, dest_conn=dst, migration_db=db, logger=logger).migrate(L2)
    analysis2, plan2 = build_plan()
    dialog2 = PreviewDialog(analysis2, plan=plan2, dry_run=False)
    actions2 = table_column(dialog2.plan_table, 0)

    check("no CREATE rows on the repeat run", actions2.count('CREATE'), 0)
    check("EXISTS rows now shown", actions2.count('EXISTS') > 0, True)

    print("\n=== An empty plan explains its actual cause ===")
    # A single "everything is already migrated" note used to cover every case, which
    # misreported a scope that had simply been filtered out by the ignore rules.
    from core.migrator import MigrationPlan
    from core.analyzer import AnalysisResult

    # Dialogs must be kept alive: if the Python wrapper is discarded, Qt frees the
    # underlying C++ widget and reading notes_text raises RuntimeError.
    built_dialogs = []

    def note_for(counts, total, **plan_fields):
        stub = AnalysisResult(base_dn='OU=X,DC=s,DC=alt')
        stub.counts_by_type = counts
        stub.total_objects = total
        empty = MigrationPlan('OU=X,DC=s,DC=alt', 'OU=X,DC=d,DC=alt')
        empty.ignored_count = counts.get('ignored', 0)
        empty.unsupported_count = counts.get('unsupported', 0)
        for name, value in plan_fields.items():
            setattr(empty, name, value)
        dialog = PreviewDialog(stub, plan=empty)
        built_dialogs.append(dialog)
        return dialog.notes_text.toPlainText()

    base_counts = {'ou': 0, 'user': 0, 'group': 0, 'contact': 0,
                   'unsupported': 0, 'ignored': 0}

    filtered = note_for({**base_counts, 'ignored': 3}, 3)
    check("filtered-out scope blames the filters",
          'filtered out' in filtered, True)
    check("filtered-out scope does NOT claim it was already migrated",
          'already been migrated' in filtered, False)

    empty_scope = note_for(base_counts, 0)
    check("empty DN says nothing was found", 'Nothing found' in empty_scope, True)

    migrated = note_for(base_counts, 1,
                        exists=[('CN=a,OU=X,DC=s,DC=alt',
                                 'CN=a,OU=X,DC=d,DC=alt', 'user')])
    check("genuinely migrated scope says so",
          'already been migrated' in migrated, True)

    conflicted = note_for(base_counts, 1,
                          conflict=[('CN=b,OU=X,DC=s,DC=alt',
                                     'CN=b,OU=X,DC=d,DC=alt', 'user')])
    check("all-conflict scope points at the conflicts",
          'in conflict' in conflicted, True)

    print("\n=== Degrades safely without a plan ===")
    no_plan = PreviewDialog(analysis, plan=None)
    check("constructs without a plan", isinstance(no_plan, PreviewDialog), True)
    check("plan table empty", no_plan.plan_table.rowCount(), 0)
    check("says the destination was not checked",
          'not checked' in no_plan.notes_text.toPlainText().lower(), True)
    check("counts tab still populated", no_plan.counts_table.rowCount() > 0, True)

    db.close()

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == '__main__':
    sys.exit(main())
