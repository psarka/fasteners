# -*- coding: utf-8 -*-

# Copyright (C) 2014 Yahoo! Inc. All Rights Reserved.
# Copyright 2011 OpenStack Foundation.
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import contextlib
import threading


class ThreadMechanism1:
    can_share = False
    can_block = True
    can_switch = False
    available = True

    def __init__(self):
        self._lock = threading.Lock()

    def lock(self, blocking):
        self._lock.acquire(blocking=blocking)

    def unlock(self):
        self._lock.release()


class ThreadMechanism2:
    can_share = True
    can_block = True
    can_switch = False
    available = True

    def __init__(self):
        self._cond = threading.Condition()
        self._readers = set()
        self._writers = set()

    def lock(self, exclusive, blocking):
        me = threading.current_thread()

        entry_condition = (
            lambda: not self._writers and not self._readers if exclusive else
            lambda: not self._writers
        )

        group_to_add = self._writers if exclusive else self._readers
        timeout = None if blocking else 0

        with self._cond:
            if self._cond.wait_for(entry_condition, timeout):
                group_to_add.add(me)
                return True
            else:
                return False

    def unlock(self):
        me = threading.current_thread()
        self._readers.remove(me)
        self._writers.remove(me)


class ReaderWriterLock(object):
    """A reader/writer lock.

    This lock allows for simultaneous readers to exist but only one writer
    to exist for use-cases where it is useful to have such types of locks.

    Currently a reader can not escalate its read lock to a write lock and
    a writer can not acquire a read lock while it is waiting on the write
    lock.

    In the future these restrictions may be relaxed.
    """

    def __init__(self):
        self._writer = None
        self._pending_writers = collections.deque()
        self._readers = {}
        self._cond = threading.Condition()
        self._current_thread = threading.current_thread

    def is_writer(self):
        """Returns if the caller is the active writer."""
        return self._current_thread() == self._writer

    def is_reader(self):
        """Returns if the caller is one of the readers."""
        return self._current_thread() in self._readers

    @contextlib.contextmanager
    def read_lock(self):
        """Context manager that grants a read lock.

        Will wait until no active or pending writers.

        Raises a ``RuntimeError`` if a pending writer tries to acquire
        a read lock.
        """
        me = self._current_thread()
        with self._cond:
            while True:
                if self._writer is None or self._writer == me:
                    if me in self._readers:
                        # ok to get a lock if current thread already has one
                        self._readers[me] += 1
                        break
                    elif not self._pending_writers:
                        self._readers[me] = 1
                        break
                # An active or pending writer; guess we have to wait.
                self._cond.wait()
        try:
            yield self
        finally:
            # I am no longer a reader, remove *one* occurrence of myself.
            with self._cond:
                self._readers[me] -= 1
                if self._readers[me] == 0:
                    del self._readers[me]
                self._cond.notify_all()

    @contextlib.contextmanager
    def write_lock(self):
        """Context manager that grants a write lock.

        Will wait until no active readers. Blocks readers after acquiring.

        Guaranteed for locks to be processed in fair order (FIFO).

        Raises a ``RuntimeError`` if an active reader attempts to acquire
        a lock.
        """
        me = self._current_thread()
        if me in self._readers and me != self._writer:
            raise RuntimeError("Reader %s to writer privilege"
                               " escalation not allowed" % me)
        if me == self._writer:
            # Already the writer; this allows for basic reentrancy.
            yield self
        else:
            with self._cond:
                self._pending_writers.append(me)
                self._cond.wait_for(lambda: not self._readers and
                                            self._writer is None and
                                            self._pending_writers[0] == me)
                self._writer = self._pending_writers.popleft()
            try:
                yield self
            finally:
                with self._cond:
                    self._writer = None
                    self._cond.notify_all()
