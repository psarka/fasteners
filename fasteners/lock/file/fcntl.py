# Copyright 2021 Fasteners developers.
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
import atexit
from collections import defaultdict
from contextlib import contextmanager
import math
from pathlib import Path
from typing import Iterable
from typing import Union

from fasteners.mechanism.file import FcntlMechanism
from fasteners.time import delayed_loop


class FcntlLock:
    mechanism = FcntlMechanism

    def __init__(self, path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, 'a+')
        self.n_reader = defaultdict(int)
        self.n_writer = defaultdict(int)

        assert self.mechanism.available

        atexit.register(self.handle.close)

    def acquire_read_lock(self,
                          byte: int = 0,
                          timeout: float = math.inf,
                          delay: Union[float, Iterable[float]] = 0.01):

        if self.n_reader[byte] > 0 or self.n_writer[byte] > 0:
            self.n_reader[byte] += 1
            return True

        if timeout == math.inf:
            ok = self.mechanism.lock(self.handle, exclusive=False, blocking=True, offset=byte, length=1)
        else:
            ok = any(self.mechanism.lock(self.handle, exclusive=False, blocking=False, offset=byte, length=1)
                     for _ in delayed_loop(delay, timeout))

        if ok:
            self.n_reader[byte] = 1
            return True
        else:
            return False

    def acquire_write_lock(self,
                           byte: int = 0,
                           timeout: float = math.inf,
                           delay: Union[float, Iterable[float]] = 0.01):

        if self.n_writer[byte] > 0:
            self.n_writer[byte] += 1
            return True

        if timeout == math.inf:
            ok = self.mechanism.lock(self.handle, exclusive=True, blocking=True, offset=byte, length=1)
        else:
            ok = any(self.mechanism.lock(self.handle, exclusive=True, blocking=False, offset=byte, length=1)
                     for _ in delayed_loop(delay, timeout))

        if ok:
            self.n_writer[byte] = 1
            return True
        else:
            return False

    def release_read_lock(self, byte=0):

        if self.n_reader[byte] > 1:
            self.n_reader[byte] -= 1
        elif self.n_reader[byte] == 1:
            if self.n_writer[byte] == 0:
                self.mechanism.unlock(self.handle, offset=byte, length=1)
            self.n_reader[byte] = 0
        else:
            raise ValueError('Cannot release unaquired lock!')

    def release_write_lock(self, byte=0):

        if self.n_writer[byte] > 1:
            self.n_writer[byte] -= 1
        elif self.n_writer[byte] == 1:
            if self.n_reader[byte] > 0:
                ok = self.mechanism.lock(self.handle, exclusive=False, blocking=False, offset=byte, length=1)
                assert ok, 'This must succeed as we already hold exclusive lock'
            else:
                self.mechanism.unlock(self.handle, offset=byte, length=1)
            self.n_writer[byte] = 1
        else:
            raise ValueError('Cannot release unaquired lock!')

    @contextmanager
    def write_lock(self,
                   byte: int = 0,
                   timeout: float = math.inf,
                   delay: Union[float, Iterable[float]] = 0.01):

        if self.acquire_write_lock(byte=byte, timeout=timeout, delay=delay):
            try:
                yield
            finally:
                self.release_write_lock()
        else:
            raise ValueError('Could not acquire the lock!')

    @contextmanager
    def read_lock(self,
                  byte: int = 0,
                  timeout: float = math.inf,
                  delay: Union[float, Iterable[float]] = 0.01):

        if self.acquire_read_lock(byte=byte, timeout=timeout, delay=delay):
            try:
                yield
            finally:
                self.release_read_lock()
        else:
            raise ValueError('Could not acquire the lock!')
