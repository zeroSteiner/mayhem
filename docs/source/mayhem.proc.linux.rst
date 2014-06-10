:mod:`mayhem.proc.linux` --- Linux manipulation classes
=======================================================

.. module:: mayhem.proc.linux
   :synopsis: Linux manipulation classes

This module contains classes functions and exceptions specific to POSIX
Linux environments.

Functions
---------

.. autofunction:: mayhem.proc.linux.get_errno

.. autofunction:: mayhem.proc.linux.parse_proc_maps

Classes
-------

.. autoclass:: mayhem.proc.linux.LinuxMemoryRegion
   :members:
   :undoc-members:

.. autoclass:: mayhem.proc.linux.LinuxProcess
   :members:
   :special-members: __init__

Exceptions
----------

.. autoexception:: mayhem.proc.linux.LinuxProcessError
   :members:
   :undoc-members:
