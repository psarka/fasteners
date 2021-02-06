# msvcrt
from fasteners.mechanism.file.abstract import FileLockingMechanism

try:
    import msvcrt
except ImportError:
    msvcrt = None


class MsvcrtMechanism(FileLockingMechanism):
    """
    A file locking mechanism based on msvcrt.
    """
    available = msvcrt is not None
    can_share = False
    can_block = False
    can_switch = False

    @staticmethod
    def lock(handle):
        """Acquire (if available immediately) an exclusive lock on the file

        Acquiring a lock can fail if the handle is already locked by another
        process, or because of some unexpected issue. The former (normal)
        failure is reported by the return value, the latter by an exception.

        msvcrt mechanism does not support shared locks, and does not support
        blocking until a lock is acquired.

        Parameters
        ----------
        handle:
            File handle

        Returns
        -------
        bool
            Whether a lock was acquired
        """
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

    @staticmethod
    def unlock(handle):
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
