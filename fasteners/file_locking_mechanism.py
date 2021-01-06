# -*- coding: utf-8 -*-

# Copyright 2011 OpenStack Foundation.
# Copyright 2021 Paulius Šarka.
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
"""
file_locking_mechanism module faithfully and thinly (but sanely!) wraps all
the available file locking mechanisms. Currently it exposes all the possible
file locking mechanisms enabled by python standard library, and in the future
it will broaden to include features and mechanisms that are only available
through C extensions.

These mechanisms can be used on their own and will be a part of public
fasteners API, or can be further wrapped on top to produce a syntactically
sweeter locks.
"""
import abc
import errno
import logging
import os
import struct

from fasteners.typing import Literal

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

try:
    from fcntl import F_OFD_SETLK
    from fcntl import F_OFD_SETLKW
except ImportError:
    F_OFD_SETLK = None
    F_OFD_SETLKW = None

RelativeTo = Literal['start', 'current', 'end']
Start = Literal['start']


class FileLockingMechanism(abc.ABC):
    can_share: bool
    can_block: bool
    can_switch: bool

    @staticmethod
    @abc.abstractmethod
    def lock(handle,
             exclusive: bool,
             blocking: bool) -> bool:
        """Acquire a lock

        Acquiring lock can fail if the handle is already locked by another
        process, or because of some unexpected issue. The former (normal)
        failure is reported by the return value, the latter by an exception.

        Parameters
        ----------
        handle:
            File handle
        exclusive:
            Whether to acquire an exclusive or shared lock
        blocking:
            Whether to block until a lock is acquired

        Returns
        -------
        bool
            Whether a lock was acquired
        """

    @staticmethod
    @abc.abstractmethod
    def unlock(handle):
        """Release a lock

        Releasing can fail if a lock is not held (nothing to release), or
        because of some unexpected issue. In both cases, an exception is raised.

        Parameters
        ----------
        handle:
            File handle
        """

    @abc.abstractmethod
    def check_availability(self):
        """Check if the mechanism is available on the platform that is trying
        to use it.

        Raises
        ------
        OSError
            In case it is not available
        """


class FcntlMechanism(FileLockingMechanism):
    """
    A file locking mechanism based on fcntl.
    """
    can_share = True
    can_block = True
    can_switch = True

    def check_availability(self):
        if fcntl is None:
            raise OSError('This operating system does not support fcntl locking mechanism!')

    @staticmethod
    def lock(handle,
             exclusive: bool,
             blocking: bool,
             offset: int = 0,
             length: int = 0,
             relative_to: RelativeTo = 'start') -> bool:
        """Acquire a lock on the byte range of the file.

        The byte range is computed as
            [relative_to + offset, relative_to + offset + length - 1]

        relative_to can be one of
            [start of the file, current cursor position, end of the file]
        offset is an integer such that
            relative_to + offset >= 0
        and length is a non-negative integer with 0 exceptionally meaning ∞.

        Byte range can exceed the size of the file.

        Acquiring a lock can fail if the file or range is already locked by
        another process, or because of some unexpected issue. The former
        (normal) failure is reported by the return value, the latter by an
        exception.

        Parameters
        ----------
        handle:
            File handle
        exclusive:
            Whether to acquire an exclusive or shared lock
        blocking:
            Whether to block until a lock is acquired
        offset:
            Offset (in bytes) of the byte range to lock (default=0)
        length:
            Length (in bytes) of the byte range to lock, with 0 being a special
            value meaning "until infinity" (default=0)
        relative_to:
            File position relative to which the byte range offset is computed.
            Can be either 'start' of the file, 'current' position or 'end' of
            the file. (default='start')

        Returns
        -------
        bool
            Whether a lock was acquired
        """
        flags = 0
        if exclusive:
            flags |= fcntl.LOCK_EX
        if not exclusive:
            flags |= fcntl.LOCK_SH
        if not blocking:
            flags |= fcntl.LOCK_NB

        whence = (0 if relative_to == 'start' else
                  1 if relative_to == 'current' else
                  2)

        try:
            fcntl.lockf(handle, flags, length, offset, whence)
            return True
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                return False
            else:
                raise e

    @staticmethod
    def unlock(handle,
               offset: int = 0,
               length: int = 0,
               relative_to: RelativeTo = 'start'):
        """Release a lock on the byte range of the file.

        The byte range is computed as
            [relative_to + offset, relative_to + offset + length - 1]

        relative_to can be one of
            [start of the file, current cursor position, end of the file]
        offset is an integer such that
            relative_to + offset >= 0
        and length is a non-negative integer with 0 exceptionally meaning ∞.

        Byte range can exceed the size of the file.

        Releasing a byte range for which no lock was held does nothing.

        Parameters
        ----------
        handle:
            File handle
        offset:
            Offset (in bytes) of the byte range to lock (default=0)
        length:
            Length (in bytes) of the byte range to lock, with 0 being a special
            value meaning "until infinity" (default=0)
        relative_to:
            File position relative to which the byte range offset is computed.
            Can be either 'start' of the file, 'current' position or 'end' of
            the file. (default='start')
        """
        whence = (0 if relative_to == 'start' else
                  1 if relative_to == 'current' else
                  2)
        fcntl.lockf(handle, fcntl.LOCK_UN, length, offset, whence)


class LockFileExMechanism(FileLockingMechanism):
    """
    A file locking mechanism based on LockFileEx.
    """
    can_share = True
    can_block = True
    can_switch = False

    def check_availability(self):
        if pywin32 is None or msvcrt is None:
            raise OSError('This operating system does not support LockFileEx locking mechanism!')

    @staticmethod
    def lock(handle, exclusive, blocking, offset=0, length=1):
        """Acquire a lock on the byte range of the file

        The byte range is computed as (relative to file start)
            [offset, offset + length - 1]

        offset is a non-negative integer not exceeding 2**64, and length is a
        non-negative integer not exceeding 2**64, with 0 resulting in nothing
        being locked.
        TODO (to double check above statements)

        Byte range can exceed the size of the file.

        Acquiring lock can fail if the handle is already locked by another
        process, or because of some unexpected issue. The former (normal)
        failure is reported by the return value, the latter by an exception.

        Parameters
        ----------
        handle:
            File handle
        exclusive:
            Whether to acquire an exclusive or shared lock
        blocking:
            Whether to block until a lock is acquired
        offset:
            Offset (in bytes) with respect to the file start of the byte range
            to lock (default=0)
        length:
            Length (in bytes) of the byte range to lock (default=1)

        Returns
        -------
        bool
            Whether a lock was acquired
        """
        flags = 0x00
        if exclusive:
            flags |= pywin32.win32con.LOCKFILE_EXCLUSIVE_LOCK
        if not blocking:
            flags |= pywin32.win32con.LOCKFILE_FAIL_IMMEDIATELY

        length_high = length >> 32
        length_low = length & 0xffffffff

        offset_high = offset >> 32
        offset_low = offset & 0xffffffff

        handle = msvcrt.get_osfhandle(handle.fileno())

        overlapped = pywin32.pywintypes.OVERLAPPED(
            pywin32.pywintypes.c_void_p(),
            pywin32.pywintypes.c_void_p(),
            pywin32.pywintypes.DummyUnion(pywin32.pywintypes.DummyStruct(offset_low, offset_high),
                                          pywin32.pywintypes.c_void_p()),
            pywin32.pywintypes.HANDLE()
        )

        pointer = pywin32.win32file.pointer(overlapped)

        ok = pywin32.win32file.LockFileEx(handle, flags, 0, length_low, length_high, pointer)
        if ok:
            return True
        else:
            last_error = pywin32.win32file.GetLastError()
            if last_error == pywin32.win32file.ERROR_LOCK_VIOLATION:
                return False
            else:
                raise OSError(last_error)

    @staticmethod
    def unlock(handle, offset=0, length=1):
        """Release a lock on the byte range of the file

        The byte range is computed as (relative to file start)
            [offset, offset + length - 1]

        offset is a non-negative integer not exceeding 2**64, and length is a
        non-negative integer not exceeding 2**64, with 0 resulting in nothing
        being locked.
        TODO (double check above statements)

        Byte range can exceed the size of the file.

        Releasing a byte range for which no lock was held does nothing.
        TODO (double check above statement)

        Parameters
        ----------
        handle:
            File handle
        offset:
            Offset (in bytes) with respect to the file start of the byte range
            to lock (default=0)
        length:
            Length (in bytes) of the byte range to lock (default=1)
        """
        handle = msvcrt.get_osfhandle(handle.fileno())

        length_high = length >> 32
        length_low = length & 0xffffffff

        offset_high = offset >> 32
        offset_low = offset & 0xffffffff

        handle = msvcrt.get_osfhandle(handle.fileno())

        overlapped = pywin32.pywintypes.OVERLAPPED(
            pywin32.pywintypes.c_void_p(),
            pywin32.pywintypes.c_void_p(),
            pywin32.pywintypes.DummyUnion(pywin32.pywintypes.DummyStruct(offset_low, offset_high),
                                          pywin32.pywintypes.c_void_p()),
            pywin32.pywintypes.HANDLE()
        )

        pointer = pywin32.win32file.pointer(overlapped)

        ok = pywin32.win32file.UnlockFileEx(handle, 0, length_low, length_high, pointer)
        if ok:
            return True
        if not ok:
            raise OSError(pywin32.win32file.GetLastError())


class MsvcrtMechanism(FileLockingMechanism):
    """
    A file locking mechanism based on msvcrt.
    """
    can_share = False
    can_block = False
    can_switch = False

    def check_availability(self):
        if msvcrt is None:
            raise OSError('This operating system does not support msvcrt locking mechanism!')

    @staticmethod
    def lock(handle, exclusive: Literal[True] = True, blocking: Literal[False] = False):
        """Acquire a lock on the file

        Acquiring lock can fail if the handle is already locked by another
        process, or because of some unexpected issue. The former (normal)
        failure is reported by the return value, the latter by an exception.

        msvcrt mechanism does not support shared locks, and does not support
        blocking until a lock is acquired.

        Parameters
        ----------
        handle:
            File handle
        exclusive:
            Whether to acquire an exclusive or shared lock. Must be equal to
            True as only exclusive lock is supported (default = True)
        blocking:
            Whether to block until a lock is acquired. Must be equal to False,
            as blocking is not supported (default = False)

        Returns
        -------
        bool
            Whether a lock was acquired
        """
        if not exclusive:
            raise ValueError('msvcrt does not support shared locks!')

        if blocking:
            raise ValueError('msvcrt does not support blocking!')

        fileno = handle.fileno()
        msvcrt.locking(fileno, msvcrt.LK_NBLCK, 1)

    @staticmethod
    def unlock(handle):
        fileno = handle.fileno()
        msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)


class FlockMechanism(FileLockingMechanism):
    """A file locking mechanism based on a python interpretation of flock"""
    can_share = True
    can_block = True
    can_switch = False

    def check_availability(self):
        if fcntl is None:
            raise OSError('This operating system does not support flock locking mechanism!')

    @staticmethod
    def lock(handle, exclusive, blocking):
        """Acquire a lock on the file

        Acquiring a lock can fail if the handle is already locked by another
        process, or because of some unexpected issue. The former (normal)
        failure is reported by the return value, the latter by an exception.

        Parameters
        ----------
        handle:
            File handle
        exclusive:
            Whether to acquire an exclusive or shared lock
        blocking:
            Whether to block until a lock is acquired

        Returns
        -------
        bool
            Whether a lock was acquired
        """
        flags = 0
        if exclusive:
            flags |= fcntl.LOCK_EX
        if not exclusive:
            flags |= fcntl.LOCK_SH
        if not blocking:
            flags |= fcntl.LOCK_NB

        try:
            fcntl.flock(handle, flags)
            return True
        except OSError:
            return False

    @staticmethod
    def unlock(handle):
        fcntl.flock(handle, fcntl.LOCK_UN)


try:
    os.O_LARGEFILE
except AttributeError:
    start_len = "ll"
else:
    start_len = "qq"

_exclusive_type = struct.pack('hh' + start_len + 'hh', fcntl.F_WRLCK, 0, 0, 0, 0, 0)
_shared_type = struct.pack('hh' + start_len + 'hh', fcntl.F_RDLCK, 0, 0, 0, 0, 0)
_unlock_type = struct.pack('hh' + start_len + 'hh', fcntl.F_UNLCK, 0, 0, 0, 0, 0)


class OpenMechanism(FileLockingMechanism):

    def check_availability(self):
        if fcntl is None or F_OFD_SETLK is None:
            raise OSError('This operating system does not support open locking mechanism!')

    @staticmethod
    def lock(handle,
             exclusive: bool,
             blocking: bool,
             offset: Literal[0] = 0,
             length: Literal[0] = 0,
             relative_to: Start = 'start') -> bool:
        """Acquire a lock on an infinite byte range [0, ∞] of the file

        Acquiring a lock can fail if the handle is already locked by another
        process, or because of some unexpected issue. The former (normal)
        failure is reported by the return value, the latter by an exception.

        Parameters
        ----------
        handle:
            File handle
        exclusive:
            Whether to acquire an exclusive or shared lock
        blocking:
            Whether to block until a lock is acquired
        offset:
            Offset (in bytes) of the byte range to lock. Currently only value 0
            is supported (default=0)
        length:
            Length (in bytes) of the byte range to lock, with 0 being a special
            value meaning ∞. Currently only value 0 is supported (default=0)
        relative_to:
            File position relative to which the byte range offset is computed.
            Can be either 'start' of the file, 'current' position or 'end' of
            the file. Currently only 'start' is supported (default='start')

        Returns
        -------
        bool
            Whether a lock was acquired
        """
        lock_data = _exclusive_type if exclusive else _shared_type
        block_data = F_OFD_SETLKW if blocking else F_OFD_SETLK
        try:
            fcntl.fcntl(handle, block_data, lock_data)
            return True
        except BlockingIOError:
            return False

    @staticmethod
    def unlock(handle):
        fcntl.fcntl(handle, F_OFD_SETLK, _unlock_type)
