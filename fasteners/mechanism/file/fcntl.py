import errno

try:
    import fcntl
except ImportError:
    fcntl = None

from fasteners.mechanism.file.abstract import FileLockingMechanism
from fasteners.mechanism.file.abstract import RelativeTo


class FcntlMechanism(FileLockingMechanism):
    """
    A file locking mechanism based on fcntl.
    """
    available = fcntl is not None
    can_share = True
    can_block = True
    can_switch = True

    @staticmethod
    def lock(handle,
             exclusive: bool = True,
             blocking: bool = False,
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

        if relative_to == 'start':
            whence = 0
        elif relative_to == 'current':
            whence = 1
        elif relative_to == 'end':
            whence = 2
        else:
            raise ValueError(f"relative_to should be 'start', 'current', or 'end', "
                             f"received {relative_to}!")

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
        if relative_to == 'start':
            whence = 0
        elif relative_to == 'current':
            whence = 1
        elif relative_to == 'end':
            whence = 2
        else:
            raise ValueError(f"relative_to should be 'start', 'current', or 'end', "
                             f"received {relative_to}!")

        fcntl.lockf(handle, fcntl.LOCK_UN, length, offset, whence)
