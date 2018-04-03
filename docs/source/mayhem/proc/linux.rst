:mod:`linux`
============

.. module:: linux
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
   :show-inheritance:
   :members:
   :inherited-members:
   :undoc-members:

.. autoclass:: mayhem.proc.linux.LinuxProcess
   :show-inheritance:
   :members:
   :special-members: __init__

Exceptions
----------

.. autoexception:: mayhem.proc.linux.LinuxProcessError
   :show-inheritance:
   :members:
   :inherited-members:
   :undoc-members:
