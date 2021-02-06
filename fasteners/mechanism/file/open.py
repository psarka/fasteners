import ctypes
import sysconfig

try:
    import fcntl

    # TODO check if on linux >= 3.15

    libc = ctypes.cdll.LoadLibrary('libc.so.6')
    libc_fcntl = libc.fcntl

    type_of_size = {ctypes.sizeof(ctypes.c_short): ctypes.c_short,
                    ctypes.sizeof(ctypes.c_int): ctypes.c_int,
                    ctypes.sizeof(ctypes.c_long): ctypes.c_long,
                    ctypes.sizeof(ctypes.c_longlong): ctypes.c_longlong}

    print(type_of_size)

    # TODO handle dict carefully

    off_t = type_of_size[sysconfig.get_config_var('SIZEOF_OFF_T')]
    pid_t = type_of_size[sysconfig.get_config_var('SIZEOF_PID_T')]

    print(off_t)
    print(pid_t)


    class StructFlock(ctypes.Structure):
        _fields_ = [('l_type', ctypes.c_short),
                    ('l_whence', ctypes.c_short),
                    ('l_start', off_t),
                    ('l_len', off_t),
                    ('l_pid', pid_t)]

except (ImportError, OSError, AttributeError):
    libc_fcntl = None
    fcntl = None

from fasteners.mechanism.file.abstract import FileLockingMechanism
from fasteners.mechanism.file.abstract import RelativeTo

F_OFD_SETLK = 37
F_OFD_SETLKW = 38


class OpenMechanism(FileLockingMechanism):
    available = fcntl is not None and libc_fcntl is not None
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
        l_type = fcntl.F_WRLCK if exclusive else fcntl.F_RDLCK

        if relative_to == 'start':
            whence = 0
        elif relative_to == 'current':
            whence = 1
        elif relative_to == 'end':
            whence = 2
        else:
            raise ValueError(f"relative_to should be 'start', 'current', or 'end', "
                             f"received {relative_to}!")

        lock_data = StructFlock(l_type=l_type,
                                l_whence=whence,
                                l_start=offset,
                                l_len=length)

        command = F_OFD_SETLKW if blocking else F_OFD_SETLK

        return libc_fcntl(handle.fileno(), command, ctypes.pointer(lock_data)) == 0

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

        lock_data = StructFlock(l_type=fcntl.F_UNLCK,
                                l_whence=whence,
                                l_start=offset,
                                l_len=length)

        ok = libc_fcntl(handle.fileno(), F_OFD_SETLK, ctypes.pointer(lock_data))

        assert ok == 0
