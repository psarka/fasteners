# Copyright 2021 Fasteners developers
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
it will include features and mechanisms that are only available through C
extensions.

These mechanisms can be used on their own and will be a part of public
fasteners API, or can be further wrapped on top to produce a syntactically
sweeter locks.
"""
import abc

from fasteners.typing import Literal


class FileLockingMechanism(abc.ABC):
    """File locking Mechanism"""

    can_share = False
    """Whether the mechanism supports shared locks"""

    can_block = False
    """Whether the mechanism supports blocking until lock is acquired"""

    can_switch = False
    """Whether the mechanism can atomically switch shared vs exclusive locks"""

    available = False
    """Whether the mechanism is available on the current platform"""

    @staticmethod
    @abc.abstractmethod
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

    @staticmethod
    @abc.abstractmethod
    def unlock(handle):
        """Release the previously acquired lock

        Parameters
        ----------
        handle:
            File handle
        """


RelativeTo = Literal['start', 'current', 'end']
