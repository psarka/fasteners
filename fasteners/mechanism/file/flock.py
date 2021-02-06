try:
    from ctypes import cdll
    import fcntl

    libc = cdll.LoadLibrary('libc.so.6')
    libc_flock = libc.flock
except (ImportError, OSError, AttributeError):
    libc_flock = None
    fcntl = None

from fasteners.mechanism.file.abstract import FileLockingMechanism


class FlockMechanism(FileLockingMechanism):
    available = libc_flock is not None
    can_share = True
    can_block = True
    can_switch = True

    @staticmethod
    def lock(handle, exclusive: bool = True, blocking: bool = False):
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

        return libc_flock(handle.fileno(), flags) == 0

    @staticmethod
    def unlock(handle):
        libc_flock(handle.fileno(), fcntl.LOCK_UN)
