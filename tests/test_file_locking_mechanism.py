import queue
from textwrap import dedent as dd

import pytest

from tests.process_tester import Tester
from fasteners.file_locking_mechanism import FcntlMechanism
from fasteners.file_locking_mechanism import PythonFlockMechanism
from fasteners.file_locking_mechanism import LockFileExMechanism
from fasteners.file_locking_mechanism import MsvcrtMechanism
from fasteners.file_locking_mechanism import OpenMechanism

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
        ok = t1.eval('a.lock(handle, exclusive=True, blocking=False)')
        assert ok

        ok = t2.eval('a.lock(handle, exclusive=True, blocking=False)')
        assert not ok

        # now unlock and check that is unlocked
        t1.exec('a.unlock(handle)')

        ok = t2.eval('a.lock(handle, exclusive=True, blocking=False)')
        assert ok


@pytest.mark.parametrize('mechanism', filter(lambda x: x.available and x.can_block, mechanisms))
def test_exclusive_blocking(mechanism, tmp_path):
    with Tester() as t1, Tester() as t2:
        setup = dd(f"""
        from fasteners.file_locking_mechanism import FcntlMechanism
        handle = open('{tmp_path / 'file'}', 'a+')
        a = FcntlMechanism()
        """)

        t1.exec(setup)
        t2.exec(setup)

        # lock and check that is locked
        ok = t1.eval('a.lock(handle, blocking=True)')
        assert ok

        with pytest.raises(queue.Empty):
            t2.eval('a.lock(handle, blocking=True)', timeout=3)

        # now unlock and check that is unlocked
        ok = t1.exec('a.unlock(handle)')
        assert ok is None

        ok = t2.eval('a.lock(handle, blocking=True)')
        assert ok
