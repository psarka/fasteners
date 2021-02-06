try:
    import msvcrt
    from fasteners import pywin32
except ImportError:
    pywin32 = None
    msvcrt = None

from fasteners.mechanism.file.abstract import FileLockingMechanism


class LockFileExMechanism(FileLockingMechanism):
    """
    A file locking mechanism based on LockFileEx.
    """
    available = pywin32 is not None and msvcrt is not None
    can_share = True
    can_block = True
    can_switch = False

    @staticmethod
    def lock(handle,
             exclusive: bool = True,
             blocking: bool = False,
             offset: int = 0,
             length: int = 1):
        """Acquire a lock on the byte range of the file

        The byte range is computed as (relative to file start)
            [offset, offset + length - 1]

        offset is a non-negative integer not exceeding 2**64, and length is a
        non-negative integer not exceeding 2**64, with length 0 resulting in
        nothing being locked.
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
    def unlock(handle, offset: int = 0, length: int = 1):
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
