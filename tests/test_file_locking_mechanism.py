import queue
from textwrap import dedent as dd
import time

import pytest

from fasteners.mechanism.file_locking_mechanism import FcntlMechanism
from fasteners.mechanism.file_locking_mechanism import LockFileExMechanism
from fasteners.mechanism.file_locking_mechanism import MsvcrtMechanism
from fasteners.mechanism.file_locking_mechanism import OpenMechanism
from fasteners.mechanism.file_locking_mechanism import PythonFlockMechanism
from tests.process_tester import Tester

mechanisms = [FcntlMechanism,
              PythonFlockMechanism,
              LockFileExMechanism,
              MsvcrtMechanism,
              OpenMechanism]


@pytest.mark.parametrize('mechanism', filter(lambda x: x.available, mechanisms))
def test_exclusive_nonblocking(tmp_path, mechanism):
    with Tester() as t1, Tester() as t2:
        setup = dd(f"""
        from fasteners.file_locking_mechanism import {mechanism.__name__}
        handle = open('{tmp_path / 'file'}', 'a+')
        a = {mechanism.__name__}()
        """)

        t1.exec(setup)
        t2.exec(setup)

        # lock and check that is locked
        ok = t1.eval('a.lock(handle)')
        assert ok

        ok = t2.eval('a.lock(handle)')
        assert not ok

        # now unlock and check that is unlocked
        t1.exec('a.unlock(handle)')

        ok = t2.eval('a.lock(handle)')
        assert ok


@pytest.mark.parametrize('mechanism', filter(lambda x: x.available, mechanisms))
def test_release_after_crash(mechanism, tmp_path):
    with Tester() as t1, Tester() as t2:
        setup = dd(f"""
        from fasteners.file_locking_mechanism import {mechanism.__name__}
        handle = open('{tmp_path / 'file'}', 'a+')
        a = {mechanism.__name__}()
        """)

        t1.exec(setup)
        t2.exec(setup)

        # lock and crash
        ok = t1.eval('a.lock(handle)')
        assert ok

        t1.p.terminate()
        time.sleep(0.1)  # give OS time to release the lock

        # see that it becomes unlocked
        ok = t2.eval('a.lock(handle)', timeout=3)
        assert ok


@pytest.mark.parametrize('mechanism', filter(lambda x: x.available and x.can_block, mechanisms))
def test_exclusive_blocking(mechanism, tmp_path):
    with Tester() as t1, Tester() as t2:
        setup = dd(f"""
        from fasteners.file_locking_mechanism import {mechanism.__name__}
        handle = open('{tmp_path / 'file'}', 'a+')
        a = {mechanism.__name__}()
        """)

        t1.exec(setup)
        t2.exec(setup)

        # lock and check that competing blocking attempt hangs:
        ok = t1.eval('a.lock(handle, blocking=True)')
        assert ok

        with pytest.raises(queue.Empty):
            t2.eval('a.lock(handle, blocking=True)', timeout=3)

        # TODO async exec wait to become available

        # now unlock and check that is unlocked
        ok = t1.exec('a.unlock(handle)')
        assert ok is None

        ok = t2.eval('a.lock(handle, blocking=True)')
        assert ok


@pytest.mark.parametrize('mechanism', filter(lambda x: x.available and x.can_share, mechanisms))
def test_shared_blocking(mechanism, tmp_path):
    with Tester() as t1, Tester() as t2:
        setup = dd(f"""
        from fasteners.file_locking_mechanism import {mechanism.__name__}
        handle = open('{tmp_path / 'file'}', 'a+')
        a = {mechanism.__name__}()
        """)

        t1.exec(setup)
        t2.exec(setup)

        # lock and check that competing blocking attempt hangs:
        ok = t1.eval('a.lock(handle, blocking=True)')
        assert ok

        with pytest.raises(queue.Empty):
            t2.eval('a.lock(handle, blocking=True)', timeout=3)

        # now unlock and check that is unlocked
        ok = t1.exec('a.unlock(handle)')
        assert ok is None

        ok = t2.eval('a.lock(handle, blocking=True)')
        assert ok
