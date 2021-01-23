from contextlib import contextmanager
import math


class Lock:

    def acquire(self, timeout=math.inf, shared=False): ...

    def release(self): ...

    @contextmanager
    def locked(self, timeout=math.inf, shared=False): ...


class Mechanism:

    @staticmethod
    def lock(handle, blocking, shared): ...

    @staticmethod
    def unlock(handle): ...

