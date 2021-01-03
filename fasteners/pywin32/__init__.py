"""
Exposes the minimal amount of code to use Win32 native file locking. We only
need two APIs, so this is far lighter weight than pulling in all of pywin32.
"""

from fasteners.pywin32 import pywintypes
from fasteners.pywin32 import win32con
from fasteners.pywin32 import win32file

