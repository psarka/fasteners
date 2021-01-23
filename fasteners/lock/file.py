# -*- coding: utf-8 -*-

# Copyright 2011 OpenStack Foundation.
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
import abc
from contextlib import contextmanager
import errno
import functools
import logging
import math
import os
from pathlib import Path
import threading
import time
import warnings

from fasteners import _utils
from fasteners.mechanism.file import FcntlMechanism
from fasteners.mechanism.file import FileLockingMechanism
from fasteners.mechanism.file import LockFileExMechanism
from fasteners.mechanism.file import MsvcrtMechanism
from fasteners.mechanism.file import PythonFlockMechanism
from fasteners.mechanism.file import OpenMechanism

LOG = logging.getLogger(__name__)


class Backoff:
    pass


class Linear:
    def __init__(self, start, step, end):
        self.start = start
        self.step = step
        self.end = end
        self._duration = start - step

    def wait_for(self):
        self._duration = min(self.end, self._duration + self.step)
        return self._duration


class FcntlLock:

    mechanism = FcntlMechanism

    def __init__(self, path):
        self.path = Path(path).resolve()
        self.handle = None

        assert self.mechanism.available

    def acquire_read_lock(self,
                          timeout: float = math.inf,
                          backoff: Backoff = Linear(0.01, 0.01, 0.1)):

        self.path.parent.mkdir(parents=True, exist_ok=True)

        if self.handle is None:
            self.handle = open(self.path, 'a+')

        if timeout == 0:
            gotten = self.mechanism.lock(self.handle, exclusive=False, blocking=False)
        elif timeout == math.inf:
            gotten = self.mechanism.lock(self.handle, exclusive=False, blocking=True)
        else:
            gotten = False
            for _ in time_something(backoff, timeout):
                gotten = self.mechanism.lock(self.handle, exclusive=False, blocking=False)
                if gotten:
                    break

        return gotten

    def acquire_write_lock(self):
        ...

    def release_read_lock(self):
        ...

    def release_write_lock(self):
        ...


class BaseInterProcessLock(object):
    MAX_DELAY = 0.1
    """
    Default maximum delay we will wait between attempts to acquire the lock (when
    it's busy/being held by another process).
    """

    DELAY_INCREMENT = 0.01
    """
    Default increment of the delay between attempts to acquire the lock. The delay
    will start at DELAY_INCREMENTAL and increase by DELAY_INCREMENTAL every attempt 
    until MAX_DELAY is reached.
    """

    @property
    @abc.abstractmethod
    def mechanism(self) -> FileLockingMechanism:
        ...

    def __init__(self, path, sleep_func=time.sleep, logger=None):

        if not self.mechanism.available:
            raise OSError(f'This operating system does not support {self.mechanism.__name__}!')

        self.lockfile = None
        self.path = _utils.canonicalize_path(path)
        self.acquired = False
        self.sleep_func = sleep_func
        self.logger = _utils.pick_first_not_none(logger, LOG)

    def acquire(self,
                blocking: bool = True,
                delay: float = DELAY_INCREMENT,
                max_delay: float = MAX_DELAY,
                timeout: float = None):
        """Attempt to acquire the lock.

        Parameters
        ----------
        blocking:
            Whether to wait forever to try to acquire the lock
        delay:
            When blocking, this is the increment of the delay time
            between attempts in seconds (default = 0.01)
        max_delay:
            When blocking, this is the maximum delay time between
            attempts in seconds (default = 0.1)
        timeout
            When blocking, this is the maximum time for which acquiring
            will be attempted

        Returns
        -------
        bool
            Whether the lock was acquired or not
        """
        if delay < 0:
            raise ValueError("Delay must be greater than or equal to zero")
        if timeout is not None and timeout < 0:
            raise ValueError("Timeout must be greater than or equal to zero")
        if delay >= max_delay:
            max_delay = delay
        self._do_open()
        watch = _utils.StopWatch(duration=timeout)
        r = _utils.Retry(delay, max_delay,
                         sleep_func=self.sleep_func, watch=watch)
        with watch:
            gotten = r(self._try_acquire, blocking, watch)
        if not gotten:
            self.acquired = False
            return False
        else:
            self.acquired = True
            self.logger.log(_utils.BLATHER,
                            "Acquired file lock `%s` after waiting %0.3fs [%s"
                            " attempts were required]", self.path,
                            watch.elapsed(), r.attempts)
            return True

    def release(self):
        """Release the previously acquired lock."""
        if not self.acquired:
            raise threading.ThreadError("Unable to release an unacquired"
                                        " lock")
        try:
            self.mechanism.unlock(self.lockfile)
        except IOError:
            self.logger.exception("Could not unlock the acquired lock opened"
                                  " on `%s`", self.path)
        else:
            self.acquired = False
            try:
                self._do_close()
            except IOError:
                self.logger.exception("Could not close the file handle"
                                      " opened on `%s`", self.path)
            else:
                self.logger.log(_utils.BLATHER,
                                "Unlocked and closed file lock open on"
                                " `%s`", self.path)

    def __enter__(self):
        gotten = self.acquire()
        if not gotten:
            # This shouldn't happen, but just incase...
            raise threading.ThreadError("Unable to acquire a file lock"
                                        " on `%s` (when used as a"
                                        " context manager)" % self.path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

    def _try_acquire(self, blocking, watch):
        try:
            gotten = self.mechanism.lock(self.lockfile, True, blocking=blocking)
        except Exception as e:
            raise threading.ThreadError(
                "Unable to acquire lock on {} due to {}!".format(self.path, e))

        if gotten:
            return True

        if not blocking or watch.expired():
            return False

        raise _utils.RetryAgain()

    def _do_open(self):
        basedir = os.path.dirname(self.path)
        if basedir:
            made_basedir = _ensure_tree(basedir)
            if made_basedir:
                self.logger.log(_utils.BLATHER,
                                'Created lock base path `%s`', basedir)
        # Open in append mode so we don't overwrite any potential contents of
        # the target file. This eliminates the possibility of an attacker
        # creating a symlink to an important file in our lock path.
        if self.lockfile is None or self.lockfile.closed:
            self.lockfile = open(self.path, 'a')

    def _do_close(self):
        if self.lockfile is not None:
            self.lockfile.close()
            self.lockfile = None

    def exists(self):
        """Checks if the path that this lock exists at actually exists."""
        warnings.warn('.exists will be removed from the API in version 1.0. ', DeprecationWarning)
        return os.path.exists(self.path)

    def trylock(self):
        warnings.warn('.trylock will be removed from the API in version 1.0. '
                      'Use .acquire and .release instead.', DeprecationWarning)
        gotten = self.mechanism.lock(self.lockfile, True, blocking=False)
        if not gotten:
            raise IOError

    def unlock(self):
        warnings.warn('.unlock will be removed from the API in version 1.0. '
                      'Use .acquire and .release instead.', DeprecationWarning)
        self.mechanism.unlock(self.lockfile)


class BaseInterProcessReaderWriterLock(object):
    MAX_DELAY = 0.1
    """
    Default maximum delay we will wait between attempts to acquire the lock (when
    it's busy/being held by another process).
    """

    DELAY_INCREMENT = 0.01
    """
    Default increment of the delay between attempts to acquire the lock. The delay
    will start at DELAY_INCREMENTAL and increase by DELAY_INCREMENTAL every attempt 
    until MAX_DELAY is reached.
    """

    @property
    @abc.abstractmethod
    def mechanism(self) -> FileLockingMechanism:
        ...

    def __init__(self, path, sleep_func=time.sleep, logger=None):

        if not self.mechanism.available:
            raise OSError(f'This operating system does not support {self.mechanism.__name__}!')

        self.lockfile = None
        self.path = _utils.canonicalize_path(path)
        self.sleep_func = sleep_func
        self.logger = _utils.pick_first_not_none(logger, LOG)

    def acquire_read_lock(self,
                          blocking: bool = True,
                          delay: float = DELAY_INCREMENT,
                          max_delay: float = MAX_DELAY,
                          timeout: float = None):
        """Attempt to acquire a reader's lock.

        Parameters
        ----------
        blocking:
            Whether to wait forever to try to acquire the lock
        delay:
            When blocking, this is the increment of the delay time
            between attempts in seconds (default = 0.01)
        max_delay:
            When blocking, this is the maximum delay time between
            attempts in seconds (default = 0.1)
        timeout
            When blocking, this is the maximum time for which acquiring
            will be attempted

        Returns
        -------
        bool
            Whether the lock was acquired or not
        """
        return self._acquire(blocking, delay, max_delay, timeout, exclusive=False)

    def acquire_write_lock(self, blocking=True,
                           delay=DELAY_INCREMENT, max_delay=MAX_DELAY,
                           timeout=None):
        """Attempt to acquire a writer's lock.

        Parameters
        ----------
        blocking:
            Whether to wait forever to try to acquire the lock
        delay:
            When blocking, this is the increment of the delay time
            between attempts in seconds (default = 0.01)
        max_delay:
            When blocking, this is the maximum delay time between
            attempts in seconds (default = 0.1)
        timeout
            When blocking, this is the maximum time for which acquiring
            will be attempted

        Returns
        -------
        bool
            Whether the lock was acquired or not
        """
        return self._acquire(blocking, delay, max_delay, timeout, exclusive=True)

    def release_write_lock(self):
        """Release the writer's lock."""
        try:
            self.mechanism.unlock(self.lockfile)
        except IOError:
            self.logger.exception("Could not unlock the acquired lock opened"
                                  " on `%s`", self.path)
        else:
            try:
                self._do_close()
            except IOError:
                self.logger.exception("Could not close the file handle"
                                      " opened on `%s`", self.path)
            else:
                self.logger.log(_utils.BLATHER,
                                "Unlocked and closed file lock open on"
                                " `%s`", self.path)

    def release_read_lock(self):
        """Release the reader's lock."""
        try:
            self.mechanism.unlock(self.lockfile)
        except IOError:
            self.logger.exception("Could not unlock the acquired lock opened"
                                  " on `%s`", self.path)
        else:
            try:
                self._do_close()
            except IOError:
                self.logger.exception("Could not close the file handle"
                                      " opened on `%s`", self.path)
            else:
                self.logger.log(_utils.BLATHER,
                                "Unlocked and closed file lock open on"
                                " `%s`", self.path)

    @contextmanager
    def write_lock(self, delay=DELAY_INCREMENT, max_delay=MAX_DELAY):

        gotten = self.acquire_write_lock(blocking=True, delay=delay,
                                         max_delay=max_delay, timeout=None)

        if not gotten:
            # This shouldn't happen, but just in case...
            raise threading.ThreadError("Unable to acquire a file lock"
                                        " on `%s` (when used as a"
                                        " context manager)" % self.path)
        try:
            yield
        finally:
            self.release_write_lock()

    @contextmanager
    def read_lock(self, delay=DELAY_INCREMENT, max_delay=MAX_DELAY):

        self.acquire_read_lock(blocking=True, delay=delay,
                               max_delay=max_delay, timeout=None)
        try:
            yield
        finally:
            self.release_read_lock()

    def _acquire(self, blocking=True,
                 delay=DELAY_INCREMENT, max_delay=MAX_DELAY,
                 timeout=None, exclusive=True):

        if delay < 0:
            raise ValueError("Delay must be greater than or equal to zero")
        if timeout is not None and timeout < 0:
            raise ValueError("Timeout must be greater than or equal to zero")
        if delay >= max_delay:
            max_delay = delay
        self._do_open()
        watch = _utils.StopWatch(duration=timeout)
        r = _utils.Retry(delay, max_delay,
                         sleep_func=self.sleep_func, watch=watch)
        with watch:
            gotten = r(self._try_acquire, blocking, watch, exclusive)
        if not gotten:
            return False
        else:
            self.logger.log(_utils.BLATHER,
                            "Acquired file lock `%s` after waiting %0.3fs [%s"
                            " attempts were required]", self.path,
                            watch.elapsed(), r.attempts)
            return True

    def _try_acquire(self, blocking, watch, exclusive):
        try:
            gotten = self.mechanism.lock(self.lockfile, exclusive, blocking=blocking)
        except Exception as e:
            raise threading.ThreadError(
                "Unable to acquire lock on {} due to {}!".format(self.path, e))

        if gotten:
            return True

        if not blocking or watch.expired():
            return False

        raise _utils.RetryAgain()

    def _do_open(self):
        basedir = os.path.dirname(self.path)
        if basedir:
            made_basedir = _ensure_tree(basedir)
            if made_basedir:
                self.logger.log(_utils.BLATHER,
                                'Created lock base path `%s`', basedir)
        if self.lockfile is None:
            self.lockfile = open(self.path, 'a+')

    def _do_close(self):
        if self.lockfile is not None:
            self.lockfile.close()
            self.lockfile = None


class InterProcessLock(BaseInterProcessLock):
    """
    A cross platform interprocess exclusive lock.

    Depending on the platform, either fcntl or msvcrt locking mechanism
    will be used.

    The lock can be acquired and released by using the corresponding
    methods, or by using it as a context manager.
    """
    mechanism = MsvcrtMechanism() if os.name == 'nt' else FcntlMechanism()

    def __init__(self, path, sleep_func=time.sleep, logger=None):
        """
        Parameters
        ----------
        path:
            File to use for locking
        sleep_func:
            Function to use for sleeping (default=time.sleep)
        logger:
            Logger to use for logging (default=logging.getLogger(__name__))
        """
        super().__init__(path, sleep_func, logger)


class InterProcessReaderWriterLock(BaseInterProcessReaderWriterLock):
    mechanism = LockFileExMechanism() if os.name == 'nt' else FcntlMechanism()

    def __init__(self, path, sleep_func=time.sleep, logger=None):
        """
        A cross platform interprocess readers writer lock.

        Depending on the platform, either fcntl or LockFileEx locking mechanism
        will be used.

        Parameters
        ----------
        path:
            File to use for locking
        sleep_func:
            Function to use for sleeping (default=time.sleep)
        logger:
            Logger to use for logging (default=logging.getLogger(__name__))
        """
        super().__init__(path, sleep_func, logger)


class FcntlLock(BaseInterProcessLock, BaseInterProcessReaderWriterLock):
    mechanism = FcntlMechanism()

    def __init__(self, path, sleep_func=time.sleep, logger=None):
        """
        Fcntl mechanism based lock

        Can be used as a simple exclusive access lock, or as a readers
        writer lock.

        Parameters
        ----------
        path:
            File to use for locking
        sleep_func:
            Function to use for sleeping (default=time.sleep)
        logger:
            Logger to use for logging (default=logging.getLogger(__name__))
        """
        super().__init__(path, sleep_func, logger)


class LockFileExLock(BaseInterProcessLock, BaseInterProcessReaderWriterLock):
    mechanism = LockFileExMechanism()

    def __init__(self, path, sleep_func=time.sleep, logger=None):
        """
        LockFileEx mechanism based lock

        Can be used as a simple exclusive access lock, or as a readers
        writer lock.

        Parameters
        ----------
        path:
            File to use for locking
        sleep_func:
            Function to use for sleeping (default=time.sleep)
        logger:
            Logger to use for logging (default=logging.getLogger(__name__))
        """
        super().__init__(path, sleep_func, logger)


class MsvcrtLock(BaseInterProcessLock):
    mechanism = MsvcrtMechanism()

    def __init__(self, path, sleep_func=time.sleep, logger=None):
        """
        Msvcrt mechanism based exclusive lock

        Parameters
        ----------
        path:
            File to use for locking
        sleep_func:
            Function to use for sleeping (default=time.sleep)
        logger:
            Logger to use for logging (default=logging.getLogger(__name__))
        """
        super().__init__(path, sleep_func, logger)


# TODO
# class FlockLock:


# TODO
# class OpenLock:


def interprocess_write_locked(path):
    """Acquires & releases an interprocess read lock around the call into
    the decorated function"""

    lock = InterProcessReaderWriterLock(path)

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            with lock.write_lock():
                return f(*args, **kwargs)

        return wrapper

    return decorator


def interprocess_read_locked(path):
    """Acquires & releases an interprocess read lock around the call into
    the decorated function"""

    lock = InterProcessReaderWriterLock(path)

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            with lock.read_lock():
                return f(*args, **kwargs)

        return wrapper

    return decorator


def interprocess_locked(path):
    """Acquires & releases a interprocess lock around call into
       decorated function."""

    lock = InterProcessLock(path)

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            with lock:
                return f(*args, **kwargs)

        return wrapper

    return decorator
