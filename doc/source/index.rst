Fasteners |version| documentation
=================================

Fasteners is a collection of locks for threads and processes. Currently it contains
both simple locks (mutexes) and reader writer locks.

Lock for processes has the same API as the `threading.Lock` for threads:

.. code-block:: python
    import fasteners
    import threading

    lock = threading.Lock()                                 # for threads
    lock = fasteners.InterProcessLock('path/to/lock.file')  # for processes

    with lock:
        ... # exclusive access

    # or alternatively

    lock.acquire()
    ... # exclusive access
    lock.release()


Reader Writer lock has a similar API, which is the same for threads or processes:

.. code-block:: python
    import fasteners

    rw_lock = fasteners.ReaderWriterLock()                                 # for threads
    rw_lock = fasteners.InterProcessReaderWriterLock('path/to/lock.file')  # for processes

    with rw_lock.write_locked():
        ... # write access

    with rw_lock.read_locked():
        ... # read access

    # or alternatively

    rw_lock.acquire_read_lock()
    ... # read access
    rw_lock.release_read_lock()

    rw_lock.acquire_write_lock()
    ... # write access
    rw_lock.release_write_lock()

# Getting started

(bendras api)

# About the locks

(daug info)

# API

*Contents:*

.. toctree::
   :maxdepth: 3

   api/lock
   api/process_lock

   examples

.. `threading.Lock`: https://docs.python.org/3/library/threading.html#threading.Lock