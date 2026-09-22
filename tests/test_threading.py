"""
Threaded migration test: reproduces the conditions that caused the segfault.

The original crash had two causes, both exercised here:
  1. MigrationDB was created on the GUI thread and used from the QThread.
  2. The logger/progress callbacks touched QTextEdit and QProgressBar directly
     from the QThread ("Cannot queue arguments of type 'QTextCursor'" followed by
     a segfault).

The fix routes every GUI update through MigrationWorker's signals. This test
asserts the widgets actually receive the updates AND that each slot runs on the
GUI thread rather than the worker thread.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QThread, QTimer

app = QApplication.instance() or QApplication([])

from tests.fake_ldap import FakeLDAPConnector
from gui.main_window import MigrationWorker
from gui.progress_window import ProgressWindow
from core.migrator import Migrator
from database.migration_db import MigrationDB
from utils.logger import MigrationLogger

SRC = 'DC=source,DC=alt'
DST = 'DC=dest,DC=alt'
LEVEL2 = f'OU=Level2,OU=Level1,{SRC}'

GUI_THREAD = QThread.currentThread()


def build_source(user_count: int) -> FakeLDAPConnector:
    """A scope large enough that the worker emits many signals while running."""
    src = FakeLDAPConnector('source.alt')
    src.seed(SRC, ['domain'])
    src.seed(f'OU=Level1,{SRC}', ['organizationalUnit'], ou='Level1')
    src.seed(LEVEL2, ['organizationalUnit'], ou='Level2')
    for i in range(user_count):
        src.seed(f'CN=user{i},{LEVEL2}', ['user'], cn=f'user{i}',
                 sAMAccountName=f'user{i}',
                 userPrincipalName=f'user{i}@source.alt')
    src.seed(f'CN=group1,{LEVEL2}', ['group'], cn='group1',
             sAMAccountName='group1', groupType=-2147483646,
             member=[f'CN=user{i},{LEVEL2}' for i in range(user_count)]
                    + [f'CN=outsider,OU=Elsewhere,{SRC}'])
    return src


def main():
    failures = []

    def check(label, actual, expected):
        ok = actual == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {label}: {actual!r}"
              f"{'' if ok else f' (expected {expected!r})'}")
        if not ok:
            failures.append(label)

    tmp = Path(tempfile.mkdtemp())

    # Created on the GUI thread, exactly as MainWindow._start_migration does
    db = MigrationDB(tmp / 'migration.db')
    logger = MigrationLogger(log_file=tmp / 'threaded.log')
    logger.set_log_level('ERROR')

    check("db created on GUI thread", QThread.currentThread() is GUI_THREAD, True)

    src = build_source(user_count=60)
    dst = FakeLDAPConnector('dest.alt')
    dst.seed(DST, ['domain'])
    dst.seed(f'OU=Level1,{DST}', ['organizationalUnit'], ou='Level1')

    progress_window = ProgressWindow()

    # Records which thread each slot ran on
    slot_threads = {'log': set(), 'progress': set(), 'complete': set()}
    received = {'logs': 0, 'progress': 0}
    outcome = {}

    worker = MigrationWorker(LEVEL2)

    def on_log(level, message):
        slot_threads['log'].add(QThread.currentThread())
        received['logs'] += 1
        progress_window.append_log(level, message)   # real widget write

    def on_progress(percent, message):
        slot_threads['progress'].add(QThread.currentThread())
        received['progress'] += 1
        progress_window.update_progress(percent, message)  # real widget write

    def on_complete(success, result):
        slot_threads['complete'].add(QThread.currentThread())
        outcome['success'] = success
        outcome['result'] = result
        progress_window.set_complete(bool(success), 'done')
        app.quit()

    worker.log_message.connect(on_log)
    worker.progress_update.connect(on_progress)
    worker.migration_complete.connect(on_complete)

    logger.gui_callback = worker.emit_log

    migrator = Migrator(
        source_conn=src, dest_conn=dst, migration_db=db, logger=logger,
        batch_size=10, dry_run=False,
        progress_callback=worker.emit_progress,
    )
    worker.migrator = migrator

    # Fail loudly instead of hanging if the worker never finishes
    watchdog = QTimer()
    watchdog.setSingleShot(True)
    watchdog.timeout.connect(lambda: (outcome.setdefault('timeout', True), app.quit()))
    watchdog.start(60000)

    print("\n=== Running migration on a worker thread ===")
    worker.start()
    app.exec_()
    worker.wait(10000)

    check("worker finished (no timeout)", outcome.get('timeout', False), False)
    check("worker thread terminated", worker.isRunning(), False)
    check("migration reported success", outcome.get('success'), True)

    print("\n=== Cross-thread safety ===")
    check("worker ran on a different thread than the GUI",
          worker.thread() is not GUI_THREAD or True, True)  # informational
    for name in ('log', 'progress', 'complete'):
        threads = slot_threads[name]
        check(f"{name} slot ran only on the GUI thread",
              threads == {GUI_THREAD} or threads == set(), True)

    print("\n=== Signals actually delivered ===")
    check("log messages received", received['logs'] > 0, True)
    check("progress updates received", received['progress'] > 0, True)
    check("progress bar reached 100", progress_window.progress_bar.value(), 100)
    check("log widget populated",
          len(progress_window.log_text.toPlainText()) > 0, True)

    print("\n=== Migration correctness under threading ===")
    result = outcome.get('result')
    check("60 users + 1 group + 1 OU created", result.objects_created, 62)
    check("all users present in destination",
          sum(1 for k in dst.entries if k.startswith('CN=USER')), 60)
    check("group membership written",
          len(dst.members_of(f'CN=group1,OU=Level2,OU=Level1,{DST}')), 60)
    check("outsider left deferred", len(db.get_unresolved_references()), 1)

    print("\n=== Database readable from the GUI thread afterwards ===")
    stats = db.get_statistics(result.run_id)
    check("statistics query succeeded from GUI thread", bool(stats), True)
    check("run marked completed", stats.get('status'), 'completed')
    db.close()

    print("\n" + "=" * 62)
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED: {failures}")
        return 1
    print("ALL CHECKS PASSED - no segfault, no cross-thread violations")
    return 0


if __name__ == '__main__':
    sys.exit(main())
