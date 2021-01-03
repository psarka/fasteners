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
import os
import threading
import time
import warnings

from fasteners import _utils

LOG = logging.getLogger(__name__)

try:
    from fasteners import pywin32
except Exception:  # noqa
    pywin32 = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    import fcntl
except ImportError:
    fcntl = None


def _ensure_tree(path):
    """Create a directory (and any ancestor directories required).

    :param path: Directory to create
    """
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == errno.EEXIST:
            if not os.path.isdir(path):
                raise
            else:
                return False
        elif e.errno == errno.EISDIR:
            return False
        else:
            raise
    else:
        return True


# Locking mechanisms

class Mechanism(abc.ABC):

    @staticmethod
    @abc.abstractmethod
    def lock(handle, exclusive: bool):
        ...

    @staticmethod
    @abc.abstractmethod
    def unlock(handle):
        ...


class FcntlMechanism(Mechanism):

    def __init__(self):
        if fcntl is None:
            raise OSError('This operating system does not support fcntl locking mechanism!')

    @staticmethod
    def lock(handle, exclusive):

        if exclusive:
            flags = fcntl.LOCK_EX | fcntl.LOCK_NB
        else:
            flags = fcntl.LOCK_SH | fcntl.LOCK_NB

        try:
            fcntl.lockf(handle, flags)
            return True
        except (IOError, OSError) as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                return False
            else:
                raise e

    @staticmethod
    def unlock(handle):
        fcntl.lockf(handle, fcntl.LOCK_UN)


# TODO _mechanism
# TODO lockfile

class LockFileExMechanism(Mechanism):

    def __init__(self):

        if pywin32 is None:
            raise OSError('This operating system does not support pywin32 and hence LockFileEx locking mechanism!')

        if msvcrt is None:
            raise OSError('This operating system does not support msvcrt and hence LockFileEx locking mechanism!')

    @staticmethod
    def lock(handle, exclusive):

        if exclusive:
            flags = pywin32.win32con.LOCKFILE_FAIL_IMMEDIATELY | pywin32.win32con.LOCKFILE_EXCLUSIVE_LOCK
        else:
            flags = pywin32.win32con.LOCKFILE_FAIL_IMMEDIATELY

        handle = msvcrt.get_osfhandle(handle.fileno())
        pointer = pywin32.win32file.pointer(pywin32.pywintypes.OVERLAPPED())
        ok = pywin32.win32file.LockFileEx(handle, flags, 0, 1, 0, pointer)
        if ok:
            return True
        else:
            last_error = pywin32.win32file.GetLastError()
            if last_error == pywin32.win32file.ERROR_LOCK_VIOLATION:
                return False
            else:
                raise OSError(last_error)

    @staticmethod
    def unlock(handle):
        handle = msvcrt.get_osfhandle(handle.fileno())
        pointer = pywin32.win32file.pointer(pywin32.pywintypes.OVERLAPPED())
        ok = pywin32.win32file.UnlockFileEx(handle, 0, 1, 0, pointer)
        if not ok:
            raise OSError(pywin32.win32file.GetLastError())


class MSVCRTMechanism(Mechanism):

    def __init__(self):
        if pywin32 is None:
            raise OSError('This operating system does not support msvcrt locking mechanism!')

    @staticmethod
    def lock(handle, exclusive):
        if not exclusive:
            raise ValueError('msvcrt does not support shared locks!')

        fileno = handle.fileno()
        msvcrt.locking(fileno, msvcrt.LK_NBLCK, 1)

    @staticmethod
    def unlock(handle):
        fileno = handle.fileno()
        msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)


# class FlockMechanism(Mechanism):
#     pass


# class OpenMechanism(Mechanism):
#     pass


# -- Locks

class BaseInterProcessLock(object):
    """An interprocess lock."""

    MAX_DELAY = 0.1
    """
    Default maximum delay we will wait to try to acquire the lock (when
    it's busy/being held by another process).
    """

    DELAY_INCREMENT = 0.01
    """
    Default increment we will use (up to max delay) after each attempt before
    next attempt to acquire the lock. For example if 3 attempts have been made
    the calling thread will sleep (0.01 * 3) before the next attempt to
    acquire the lock (and repeat).
    """

    def __init__(self, path, mechanism: Mechanism, sleep_func=time.sleep, logger=None):
        self.lockfile = None
        self.path = _utils.canonicalize_path(path)
        self.mechanism = mechanism
        self.acquired = False
        self.sleep_func = sleep_func
        self.logger = _utils.pick_first_not_none(logger, LOG)

    def _try_acquire(self, blocking, watch):
        try:
            gotten = self.mechanism.lock(self.lockfile, True)
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

    def acquire(self, blocking=True,
                delay=DELAY_INCREMENT, max_delay=MAX_DELAY,
                timeout=None):
        """Attempt to acquire the given lock.

        :param blocking: whether to wait forever to try to acquire the lock
        :type blocking: bool
        :param delay: when blocking this is the delay time in seconds that
                      will be added after each failed acquisition
        :type delay: int/float
        :param max_delay: the maximum delay to have (this limits the
                          accumulated delay(s) added after each failed
                          acquisition)
        :type max_delay: int/float
        :param timeout: an optional timeout (limits how long blocking
                        will occur for)
        :type timeout: int/float
        :returns: whether or not the acquisition succeeded
        :rtype: bool
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

    def _do_close(self):
        if self.lockfile is not None:
            self.lockfile.close()
            self.lockfile = None

    def __enter__(self):
        gotten = self.acquire()
        if not gotten:
            # This shouldn't happen, but just incase...
            raise threading.ThreadError("Unable to acquire a file lock"
                                        " on `%s` (when used as a"
                                        " context manager)" % self.path)
        return self

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

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

    def exists(self):
        """Checks if the path that this lock exists at actually exists."""
        return os.path.exists(self.path)

    def trylock(self):
        warnings.warn('.trylock will be removed from the API in version 1.0. '
                      'Use .acquire and .release instead.', DeprecationWarning)
        gotten = self.mechanism.lock(self.lockfile, True)
        if not gotten:
            raise IOError

    def unlock(self):
        warnings.warn('.unlock will be removed from the API in version 1.0. '
                      'Use .acquire and .release instead.', DeprecationWarning)
        self.mechanism.unlock(self.lockfile)


class BaseInterProcessReaderWriterLock(object):
    """An interprocess readers writer lock."""

    MAX_DELAY = 0.1
    """
    Default maximum delay we will wait to try to acquire the lock (when
    it's busy/being held by another process).
    """

    DELAY_INCREMENT = 0.01
    """
    Default increment we will use (up to max delay) after each attempt before
    next attempt to acquire the lock. For example if 3 attempts have been made
    the calling thread will sleep (0.01 * 3) before the next attempt to
    acquire the lock (and repeat).
    """

    def __init__(self, path, mechanism: Mechanism, sleep_func=time.sleep, logger=None):
        self.lockfile = None
        self.path = _utils.canonicalize_path(path)
        self.mechanism = mechanism
        self.sleep_func = sleep_func
        self.logger = _utils.pick_first_not_none(logger, LOG)

    def _try_acquire(self, blocking, watch, exclusive):
        try:
            gotten = self.mechanism.lock(self.lockfile, exclusive)
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

    def acquire_read_lock(self, blocking=True,
                          delay=DELAY_INCREMENT, max_delay=MAX_DELAY,
                          timeout=None):

        """Attempt to acquire a reader's lock.

        :param blocking: whether to wait forever to try to acquire the lock
        :type blocking: bool
        :param delay: when blocking this is the delay time in seconds that
                      will be added after each failed acquisition
        :type delay: int/float
        :param max_delay: the maximum delay to have (this limits the
                          accumulated delay(s) added after each failed
                          acquisition)
        :type max_delay: int/float
        :param timeout: an optional timeout (limits how long blocking
                        will occur for)
        :type timeout: int/float
        :returns: whether or not the acquisition succeeded
        :rtype: bool
        """
        return self._acquire(blocking, delay, max_delay, timeout, exclusive=False)

    def acquire_write_lock(self, blocking=True,
                           delay=DELAY_INCREMENT, max_delay=MAX_DELAY,
                           timeout=None):

        """Attempt to acquire a writer's lock.

        :param blocking: whether to wait forever to try to acquire the lock
        :type blocking: bool
        :param delay: when blocking this is the delay time in seconds that
                      will be added after each failed acquisition
        :type delay: int/float
        :param max_delay: the maximum delay to have (this limits the
                          accumulated delay(s) added after each failed
                          acquisition)
        :type max_delay: int/float
        :param timeout: an optional timeout (limits how long blocking
                        will occur for)
        :type timeout: int/float
        :returns: whether or not the acquisition succeeded
        :rtype: bool
        """
        return self._acquire(blocking, delay, max_delay, timeout, exclusive=True)

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

    def _do_close(self):
        if self.lockfile is not None:
            self.lockfile.close()
            self.lockfile = None

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


# ---
# Public API


class InterProcessLock(BaseInterProcessLock):
    def __init__(self, path, sleep_func=time.sleep, logger=None):
        mechanism = MSVCRTMechanism() if os.name == 'nt' else FcntlMechanism()
        super().__init__(path, mechanism=mechanism, sleep_func=sleep_func, logger=logger)


class InterProcessReaderWriterLock(BaseInterProcessReaderWriterLock):

    def __init__(self, path, sleep_func=time.sleep, logger=None):
        mechanism = LockFileExMechanism() if os.name == 'nt' else FcntlMechanism()
        super().__init__(path, mechanism=mechanism, sleep_func=sleep_func, logger=logger)


class FcntlLock(BaseInterProcessLock, BaseInterProcessReaderWriterLock):
    def __init__(self, path, sleep_func=time.sleep, logger=None):
        super().__init__(path, mechanism=FcntlMechanism(), sleep_func=sleep_func, logger=logger)


class LockFileExLock(BaseInterProcessLock, BaseInterProcessReaderWriterLock):
    def __init__(self, path, sleep_func=time.sleep, logger=None):
        super().__init__(path, mechanism=LockFileExMechanism(), sleep_func=sleep_func, logger=logger)


class MSVCRTLock(BaseInterProcessLock):
    def __init__(self, path, sleep_func=time.sleep, logger=None):
        super().__init__(path, mechanism=MSVCRTMechanism(), sleep_func=sleep_func, logger=logger)


# class FlockLock:
#     def __init__(self, path, sleep_func=time.sleep, logger=None):
#         super().__init__(path, mechanism=FlockMechanism(), sleep_func=sleep_func, logger=logger)


# class OpenLock:
#     def __init__(self, path, sleep_func=time.sleep, logger=None):
#         super().__init__(path, mechanism=OpenMechanism(), sleep_func=sleep_func, logger=logger)


# ---


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
