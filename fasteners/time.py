import itertools
import time


def delayed_loop(delay, timeout):
    try:
        delays = iter(delay)
    except TypeError:
        delays = itertools.repeat(delay)

    while timeout >= 0:
        yield
        delay = next(delays)
        time.sleep(delay)
        timeout -= delay
